pipeline {
  agent any

  options {
    timestamps()
    disableConcurrentBuilds()
    buildDiscarder(logRotator(numToKeepStr: '20', artifactNumToKeepStr: '20'))
  }

  triggers {
    pollSCM('H/15 * * * *')
  }

  environment {
    CI = 'true'
    CARGO_TERM_COLOR = 'always'
    NPM_CONFIG_AUDIT = 'false'
    NPM_CONFIG_FUND = 'false'
    PATH = "${env.HOME}/.cargo/bin:${env.PATH}"
  }

  stages {
    stage('Checkout') {
      steps {
        checkout scm
        sh 'date +%s > .build-start-epoch'
      }
    }

    stage('Preflight (Linux deps)') {
      when {
        branch 'main'
      }
      steps {
        sh '''#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Non-Linux agent detected; skipping Linux dependency checks."
  exit 0
fi

missing_tools=()
for tool in git curl pkg-config node npm; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing_tools+=("$tool")
  fi
done

missing_libs=()
if ! pkg-config --exists gtk+-3.0; then
  missing_libs+=("gtk+-3.0")
fi

if ! pkg-config --exists webkit2gtk-4.1 && ! pkg-config --exists webkit2gtk-4.0; then
  missing_libs+=("webkit2gtk (4.1 or 4.0)")
fi

if ! pkg-config --exists libsoup-3.0 && ! pkg-config --exists libsoup-2.4; then
  missing_libs+=("libsoup (3.0 or 2.4)")
fi

if ! pkg-config --exists openssl; then
  missing_libs+=("openssl")
fi

if [[ ${#missing_tools[@]} -gt 0 || ${#missing_libs[@]} -gt 0 ]]; then
  echo "ERROR: Jenkins agent is missing required Linux build dependencies."
  if [[ ${#missing_tools[@]} -gt 0 ]]; then
    echo "Missing tools: ${missing_tools[*]}"
  fi
  if [[ ${#missing_libs[@]} -gt 0 ]]; then
    echo "Missing pkg-config libs: ${missing_libs[*]}"
  fi
  echo
  echo "Install commands (pick one for your distro):"
  echo "- Fedora/RHEL/CentOS: sudo dnf install -y git curl pkgconf-pkg-config gtk3-devel webkit2gtk4.1-devel libsoup3-devel openssl-devel libayatana-appindicator-gtk3-devel librsvg2-devel patchelf"
  echo "- Ubuntu/Debian: sudo apt-get update && sudo apt-get install -y build-essential git curl pkg-config libgtk-3-dev libwebkit2gtk-4.1-dev libsoup-3.0-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev patchelf"
  echo "- Arch: sudo pacman -Sy --needed base-devel git curl pkgconf gtk3 webkit2gtk-4.1 libsoup3 openssl libappindicator-gtk3 librsvg patchelf"
  echo "- openSUSE: sudo zypper install -y gcc gcc-c++ make git curl pkgconf-pkg-config gtk3-devel webkit2gtk3-devel libsoup-3_0-devel libopenssl-devel libayatana-appindicator-gtk3-devel librsvg-devel patchelf"
  exit 1
fi

echo "Linux dependency preflight passed."
'''
      }
    }

    stage('Ensure Rust Toolchain') {
      when {
        branch 'main'
      }
      steps {
        sh '''#!/usr/bin/env bash
set -euo pipefail

if ! command -v rustc >/dev/null 2>&1; then
  echo "rustc not found. Installing Rust via rustup..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi

"$HOME/.cargo/bin/rustup" default stable
"$HOME/.cargo/bin/rustup" component add rustfmt clippy || true
'''
      }
    }

    stage('Toolchain') {
      when {
        branch 'main'
      }
      steps {
        sh 'node --version'
        sh 'npm --version'
        sh 'rustc --version'
        sh 'cargo --version'
      }
    }

    stage('Install Dependencies') {
      when {
        branch 'main'
      }
      steps {
        sh 'npm ci'
      }
    }

    stage('Frontend Build') {
      when {
        branch 'main'
      }
      steps {
        sh 'npm run build'
      }
    }

    stage('Rust Check') {
      when {
        branch 'main'
      }
      steps {
        sh 'cargo check --manifest-path src-tauri/Cargo.toml --all-targets'
      }
    }

    stage('Native Host (Release)') {
      when {
        branch 'main'
      }
      steps {
        sh 'cargo build --release --manifest-path src-tauri/Cargo.toml'
      }
    }

    stage('Linux AppImage Build') {
      when {
        branch 'main'
      }
      steps {
        sh 'npm run tauri:build:linux'
      }
    }

    stage('Legal Bundle') {
      when {
        branch 'main'
      }
      steps {
        sh 'npm run legal:bundle'
      }
    }

    stage('Checksums') {
      when {
        branch 'main'
      }
      steps {
        sh '''#!/usr/bin/env bash
set -euo pipefail

mkdir -p build-artifacts

if [ -f src-tauri/target/release/SecurePasswordManager ]; then
  cp src-tauri/target/release/SecurePasswordManager build-artifacts/
fi

find src-tauri/target/release/bundle -type f '(' -name '*.AppImage' -o -name '*.deb' -o -name '*.rpm' ')' -exec cp {} build-artifacts/ ';' 2>/dev/null || true

if [ -d build-artifacts ] && [ "$(find build-artifacts -type f | wc -l)" -gt 0 ]; then
  (
    cd build-artifacts
    find . -maxdepth 1 -type f ! -name 'SHA256SUMS.txt' -print0 \
      | sort -z \
      | xargs -0 sha256sum > SHA256SUMS.txt
  )
fi
'''
      }
    }

    stage('Build Summary') {
      when {
        branch 'main'
      }
      steps {
        sh '''#!/usr/bin/env bash
set -euo pipefail

START_EPOCH=$(cat .build-start-epoch 2>/dev/null || echo "$(date +%s)")
END_EPOCH=$(date +%s)
ELAPSED=$((END_EPOCH - START_EPOCH))

{
  echo "Build Summary"
  echo "============="
  echo "Job: ${JOB_NAME}"
  echo "Build: #${BUILD_NUMBER}"
  echo "Branch: ${BRANCH_NAME:-unknown}"
  echo "Commit: ${GIT_COMMIT:-unknown}"
  echo "DurationSeconds: ${ELAPSED}"
  echo
  echo "Artifacts:"
  find build-artifacts -maxdepth 1 -type f -printf "- %f\\n" 2>/dev/null || echo "- none"
  if [ -f build-artifacts/SHA256SUMS.txt ]; then
    echo
    echo "Checksums:"
    cat build-artifacts/SHA256SUMS.txt
  fi
} > build-summary.txt

cat build-summary.txt
'''
      }
    }
  }

  post {
    always {
      archiveArtifacts artifacts: 'build-artifacts/**,licenses/**,build-summary.txt', allowEmptyArchive: true, fingerprint: true
    }
    failure {
      echo 'Build failed. Check stage logs and ensure Linux Tauri dependencies are installed on the Jenkins agent.'
      sh '''#!/usr/bin/env bash
set +e

MESSAGE="[${JOB_NAME} #${BUILD_NUMBER}] FAILED on branch ${BRANCH_NAME:-unknown} @ ${GIT_COMMIT:-unknown}"
echo "$MESSAGE"

if [[ -n "${NOTIFY_WEBHOOK_URL:-}" ]]; then
  python3 - <<'PY'
import json
import os
import urllib.request

url = os.getenv('NOTIFY_WEBHOOK_URL', '').strip()
if url:
    message = f"[{os.getenv('JOB_NAME')} #{os.getenv('BUILD_NUMBER')}] FAILED on branch {os.getenv('BRANCH_NAME', 'unknown')} @ {os.getenv('GIT_COMMIT', 'unknown')}"
    data = json.dumps({"text": message}).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=10).read()
PY
fi

if [[ -n "${NOTIFY_EMAIL_TO:-}" ]] && command -v mail >/dev/null 2>&1; then
  echo "$MESSAGE" | mail -s "Jenkins build failed: ${JOB_NAME} #${BUILD_NUMBER}" "$NOTIFY_EMAIL_TO"
fi
'''
    }
    success {
      sh '''#!/usr/bin/env bash
set +e
if [[ -f build-summary.txt ]]; then
  echo "----- Build Summary -----"
  cat build-summary.txt
fi
'''
    }
  }
}
