import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';

const ROOT = process.cwd();
const OUT_DIR = path.join(ROOT, 'licenses');
const NPM_OUT = path.join(OUT_DIR, 'npm');
const RUST_OUT = path.join(OUT_DIR, 'rust');
const CARGO_MANIFEST = path.join(ROOT, 'src-tauri', 'Cargo.toml');

const LICENSE_CANDIDATES = [
  'LICENSE',
  'LICENSE.md',
  'LICENSE.txt',
  'LICENCE',
  'LICENCE.md',
  'LICENCE.txt',
  'COPYING',
  'COPYING.md',
  'COPYING.txt',
  'UNLICENSE',
  'NOTICE',
  'NOTICE.md',
  'NOTICE.txt'
];

function safeName(name) {
  return name.replace(/[\\/@]/g, '_').replace(/[^a-zA-Z0-9._-]/g, '_');
}

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function tryFindLicenseFile(pkgDir, declaredLicenseFile) {
  if (declaredLicenseFile) {
    const explicit = path.resolve(pkgDir, declaredLicenseFile);
    if (fs.existsSync(explicit) && fs.statSync(explicit).isFile()) {
      return explicit;
    }
  }

  for (const candidate of LICENSE_CANDIDATES) {
    const full = path.join(pkgDir, candidate);
    if (fs.existsSync(full) && fs.statSync(full).isFile()) {
      return full;
    }
  }

  try {
    const files = fs.readdirSync(pkgDir);
    const fuzzy = files.find((name) => /^(license|licence|copying|notice)/i.test(name));
    if (fuzzy) {
      const full = path.join(pkgDir, fuzzy);
      if (fs.statSync(full).isFile()) {
        return full;
      }
    }
  } catch {
    return null;
  }

  return null;
}

function copyLicenseText(sourcePath, destinationPath) {
  ensureDir(path.dirname(destinationPath));
  fs.copyFileSync(sourcePath, destinationPath);
}

function walkNodeModules() {
  const nodeModulesDir = path.join(ROOT, 'node_modules');
  const found = [];

  function walk(dirPath) {
    let entries = [];
    try {
      entries = fs.readdirSync(dirPath, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (!entry.isDirectory() || entry.name.startsWith('.')) {
        continue;
      }

      const fullPath = path.join(dirPath, entry.name);
      if (entry.name.startsWith('@')) {
        walk(fullPath);
        continue;
      }

      const packageJsonPath = path.join(fullPath, 'package.json');
      if (!fs.existsSync(packageJsonPath)) {
        continue;
      }

      try {
        const pkg = readJson(packageJsonPath);
        const licenseExpr = pkg.license ?? pkg.licenses ?? 'UNKNOWN';
        const licenseFile = tryFindLicenseFile(fullPath);
        found.push({
          ecosystem: 'npm',
          name: pkg.name ?? entry.name,
          version: pkg.version ?? '0.0.0',
          license: typeof licenseExpr === 'string' ? licenseExpr : JSON.stringify(licenseExpr),
          packageDir: fullPath,
          licenseFile
        });
      } catch {
        // Ignore malformed package metadata.
      }
    }
  }

  walk(nodeModulesDir);
  return found.sort((a, b) => `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`));
}

function collectCargoLinuxReachablePackages() {
  const raw = execSync(
    `cargo metadata --manifest-path "${CARGO_MANIFEST}" --format-version 1 --filter-platform x86_64-unknown-linux-gnu`,
    {
      cwd: ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 64 * 1024 * 1024
    }
  );
  const metadata = JSON.parse(raw);

  const packages = new Map((metadata.packages ?? []).map((item) => [item.id, item]));
  const resolve = metadata.resolve;
  const nodes = resolve?.nodes ?? [];
  const root = resolve?.root;
  if (!root) {
    return [];
  }

  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const reachable = new Set();
  const queue = [root];

  while (queue.length > 0) {
    const current = queue.pop();
    if (!current || reachable.has(current)) {
      continue;
    }
    reachable.add(current);

    const node = nodeById.get(current);
    if (!node) {
      continue;
    }

    for (const dep of node.deps ?? []) {
      queue.push(dep.pkg);
    }
  }

  const list = [];
  for (const pkgId of reachable) {
    const pkg = packages.get(pkgId);
    if (!pkg) {
      continue;
    }
    const manifestPath = pkg.manifest_path;
    const packageDir = manifestPath ? path.dirname(manifestPath) : null;
    const licenseFile = packageDir
      ? tryFindLicenseFile(packageDir, pkg.license_file ?? null)
      : null;

    list.push({
      ecosystem: 'cargo',
      name: pkg.name,
      version: pkg.version,
      license: pkg.license ?? 'UNKNOWN',
      packageDir,
      licenseFile
    });
  }

  return list.sort((a, b) => `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`));
}

function writeJsonArtifacts(npmPackages, cargoPackages) {
  fs.writeFileSync(path.join(OUT_DIR, 'npm-licenses.snapshot.json'), JSON.stringify(npmPackages, null, 2));
  fs.writeFileSync(path.join(OUT_DIR, 'cargo-licenses.snapshot.json'), JSON.stringify(cargoPackages, null, 2));
}

function bundleLicenseFiles(packages, destinationRoot) {
  let copied = 0;
  let missing = 0;

  for (const pkg of packages) {
    const fileStem = `${safeName(pkg.name)}@${pkg.version}`;
    const metadataPath = path.join(destinationRoot, `${fileStem}.json`);
    fs.writeFileSync(
      metadataPath,
      JSON.stringify(
        {
          name: pkg.name,
          version: pkg.version,
          license: pkg.license,
          packageDir: pkg.packageDir,
          licenseFile: pkg.licenseFile
        },
        null,
        2
      )
    );

    if (pkg.licenseFile) {
      const ext = path.extname(pkg.licenseFile) || '.txt';
      const destinationPath = path.join(destinationRoot, `${fileStem}.LICENSE${ext}`);
      copyLicenseText(pkg.licenseFile, destinationPath);
      copied += 1;
    } else {
      missing += 1;
    }
  }

  return { copied, missing };
}

function countByLicense(packages) {
  const counts = new Map();
  for (const item of packages) {
    counts.set(item.license, (counts.get(item.license) ?? 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1]);
}

function writeSummary(npmPackages, cargoPackages, npmBundleStats, cargoBundleStats) {
  const generatedAt = new Date().toISOString();
  const npmCounts = countByLicense(npmPackages);
  const cargoCounts = countByLicense(cargoPackages);

  const lines = [
    '# Legal Bundle',
    '',
    `Generated at: ${generatedAt}`,
    '',
    'This folder is generated by `npm run legal:bundle` and is intended to be packaged with releases.',
    '',
    '## Contents',
    '',
    '- `npm/`: npm package license texts and metadata',
    '- `rust/`: Cargo (Linux-reachable) crate license texts and metadata',
    '- `npm-licenses.snapshot.json`: npm dependency/license snapshot',
    '- `cargo-licenses.snapshot.json`: Rust dependency/license snapshot',
    '',
    '## npm summary',
    '',
    `- Packages scanned: ${npmPackages.length}`,
    `- License files copied: ${npmBundleStats.copied}`,
    `- Packages missing detected license files: ${npmBundleStats.missing}`,
    ''
  ];

  for (const [license, count] of npmCounts) {
    lines.push(`- ${license}: ${count}`);
  }

  lines.push('', '## Rust summary (Linux reachable graph)', '', `- Crates scanned: ${cargoPackages.length}`, `- License files copied: ${cargoBundleStats.copied}`, `- Crates missing detected license files: ${cargoBundleStats.missing}`, '');

  for (const [license, count] of cargoCounts) {
    lines.push(`- ${license}: ${count}`);
  }

  lines.push('', '## Notes', '', '- Missing license-file entries are often metadata gaps; verify manually before release.', '- Keep `THIRD_PARTY_NOTICES.md` and this bundle aligned for each published version.');

  fs.writeFileSync(path.join(OUT_DIR, 'README.md'), `${lines.join('\n')}\n`);
}

function resetOutputDirs() {
  fs.rmSync(OUT_DIR, { recursive: true, force: true });
  ensureDir(NPM_OUT);
  ensureDir(RUST_OUT);
}

function main() {
  if (!fs.existsSync(path.join(ROOT, 'package.json'))) {
    throw new Error('Run this script from repository root (package.json not found).');
  }

  resetOutputDirs();

  const npmPackages = walkNodeModules();
  const cargoPackages = collectCargoLinuxReachablePackages();

  writeJsonArtifacts(npmPackages, cargoPackages);

  const npmBundleStats = bundleLicenseFiles(npmPackages, NPM_OUT);
  const cargoBundleStats = bundleLicenseFiles(cargoPackages, RUST_OUT);

  writeSummary(npmPackages, cargoPackages, npmBundleStats, cargoBundleStats);

  console.log(`[legal:bundle] Generated ${OUT_DIR}`);
  console.log(`[legal:bundle] npm packages: ${npmPackages.length}, license files copied: ${npmBundleStats.copied}, missing: ${npmBundleStats.missing}`);
  console.log(`[legal:bundle] cargo crates: ${cargoPackages.length}, license files copied: ${cargoBundleStats.copied}, missing: ${cargoBundleStats.missing}`);
}

main();
