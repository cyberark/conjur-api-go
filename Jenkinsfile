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
          steps { sh './bin/parse-changelog.sh' }
        }
      }
    }
    stage('Run Tests') {
      parallel {
        stage('Golang 1.19') {
          steps {
            sh './bin/test.sh 1.19'
            junit 'output/1.19/junit.xml'
          }
        }

        stage('Golang 1.18') {
          steps {
            sh './bin/test.sh 1.18'
            junit 'output/1.18/junit.xml'
            cobertura autoUpdateHealth: false,
                      autoUpdateStability: false,
                      coberturaReportFile: 'output/1.18/coverage.xml',
                      conditionalCoverageTargets: '30, 0, 0',
                      failUnhealthy: true,
                      failUnstable: false,
                      lineCoverageTargets: '30, 0, 0',
                      maxNumberOfBuilds: 0,
                      methodCoverageTargets: '30, 0, 0',
                      onlyStable: false,
                      sourceEncoding: 'ASCII',
                      zoomCoverageChart: false
            sh 'cp output/1.18/c.out .'
            ccCoverage("gocov", "--prefix github.com/cyberark/conjur-api-go")
          }
        }
      }
    }

    stage('Package distribution tarballs') {
      steps {
        sh './bin/package.sh'
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
