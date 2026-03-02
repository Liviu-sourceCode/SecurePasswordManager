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
  }

  stages {
    stage('Checkout') {
      steps {
        checkout scm
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
