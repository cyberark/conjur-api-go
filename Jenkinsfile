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

    stage('Run tests: Golang 1.14') {
      steps {
        sh './bin/test.sh 1.14'
        junit 'output/1.14/junit.xml'
      }
    }

    stage('Run tests: Golang 1.15') {
      steps {
        sh './bin/test.sh 1.15'
        junit 'output/1.15/junit.xml'
        cobertura autoUpdateHealth: true, autoUpdateStability: true, coberturaReportFile: 'output/1.15/coverage.xml', conditionalCoverageTargets:'30, 0, 0', failUnhealthy: true, failUnstable: false, lineCoverageTargets: '30, 0, 0', maxNumberOfBuilds: 0, methodCoverageTargets: '30, 0, 0', onlyStable: false, sourceEncoding: 'ASCII', zoomCoverageChart: false
        sh 'cp output/1.15/c.out .'
        ccCoverage("gocov", "--prefix github.com/cyberark/conjur-api-go")
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
