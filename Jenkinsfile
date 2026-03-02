pipeline {
  agent any

  options {
    timestamps()
    disableConcurrentBuilds()
    buildDiscarder(logRotator(numToKeepStr: '25'))
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
      }
    }

    stage('Preflight (Linux deps)') {
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
      steps {
        sh 'node --version'
        sh 'npm --version'
        sh 'rustc --version'
        sh 'cargo --version'
      }
    }

    stage('Install Dependencies') {
      steps {
        sh 'npm ci'
      }
    }

    stage('Frontend Build') {
      steps {
        sh 'npm run build'
      }
    }

    stage('Rust Check') {
      steps {
        sh 'cargo check --manifest-path src-tauri/Cargo.toml --all-targets'
      }
    }

    stage('Native Host (Release)') {
      steps {
        sh 'cargo build --release --manifest-path src-tauri/Cargo.toml'
      }
    }

    stage('Linux AppImage Build') {
      steps {
        sh 'npm run tauri:build:linux'
      }
    }

    stage('Legal Bundle') {
      steps {
        sh 'npm run legal:bundle'
      }
    }
  }

  post {
    always {
      archiveArtifacts artifacts: 'dist/**,licenses/**,src-tauri/target/release/SecurePasswordManager,src-tauri/target/release/bundle/**/*.AppImage,src-tauri/target/release/bundle/**/*.deb,src-tauri/target/release/bundle/**/*.rpm', allowEmptyArchive: true, fingerprint: true
    }
    failure {
      echo 'Build failed. Check stage logs and ensure Linux Tauri dependencies are installed on the Jenkins agent.'
    }
  }
}
