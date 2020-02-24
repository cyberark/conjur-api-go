#!/usr/bin/env groovy

pipeline {
  agent { label 'executor-v2' }

  options {
    timestamps()
    buildDiscarder(logRotator(numToKeepStr: '30'))
  }

  triggers {
    cron(getDailyCronString())
  }

  stages {
    stage('Validate') {
      parallel {
        stage('Changelog') {
          steps { sh './parse-changelog.sh' }
        }
      }
    }
    
    stage('Run tests') {
      steps {
        sh './test.sh'
        junit 'output/junit.xml'
      }
    }

    stage('Package distribution tarballs') {
      steps {
        sh './package.sh'
        archiveArtifacts artifacts: 'output/dist/*', fingerprint: true
      }
    }
  }

  post {
    always {
      cleanupAndNotify(currentBuild.currentResult)
    }
  }
}
