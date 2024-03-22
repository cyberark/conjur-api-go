#!/usr/bin/env groovy
@Library("product-pipelines-shared-library") _

pipeline {
  agent { label 'conjur-enterprise-common-agent' }

  options {
    timestamps()
    buildDiscarder(logRotator(numToKeepStr: '30'))
  }

  triggers {
    cron(getDailyCronString())
  }

  stages {
    stage('Scan for internal URLs') {
      steps {
        script {
          detectInternalUrls()
        }
      }
    }

    stage('Get InfraPool ExecutorV2 Agent') {
      steps {
        script {
          // Request ExecutorV2 agents for 1 hour(s)
          INFRAPOOL_EXECUTORV2_AGENT_0 = getInfraPoolAgent.connected(type: "ExecutorV2", quantity: 1, duration: 1)[0]
        }
      }
    }

    stage('Validate') {
      parallel {
        stage('Changelog') {
          steps { parseChangelog(INFRAPOOL_EXECUTORV2_AGENT_0) }
        }
      }
    }
    stage('Run Tests') {
      parallel {
        stage('Golang 1.22') {
          steps {
            script {
              INFRAPOOL_EXECUTORV2_AGENT_0.agentSh './bin/test.sh 1.22'
              INFRAPOOL_EXECUTORV2_AGENT_0.agentStash name: '1.22-out', includes: 'output/1.22/*.xml'
              unstash '1.22-out'
            }
          }
        }

        stage('Golang 1.21') {
          steps {
            script {
              INFRAPOOL_EXECUTORV2_AGENT_0.agentSh './bin/test.sh 1.21'
              INFRAPOOL_EXECUTORV2_AGENT_0.agentStash name: '1.21-out', includes: 'output/1.21/*.xml'
              unstash '1.21-out'
              cobertura autoUpdateHealth: false,
                        autoUpdateStability: false,
                        coberturaReportFile: 'output/1.21/coverage.xml',
                        conditionalCoverageTargets: '30, 0, 0',
                        failUnhealthy: true,
                        failUnstable: false,
                        lineCoverageTargets: '30, 0, 0',
                        maxNumberOfBuilds: 0,
                        methodCoverageTargets: '30, 0, 0',
                        onlyStable: false,
                        sourceEncoding: 'ASCII',
                        zoomCoverageChart: false
              INFRAPOOL_EXECUTORV2_AGENT_0.agentSh 'cp output/1.21/c.out .'
              codacy action: 'reportCoverage', filePath: "output/1.21/coverage.xml"
            }
          }
        }
      }
      post {
        always {
          junit 'output/1.22/junit.xml, output/1.21/junit.xml'
        }
      }
    }

    stage('Package distribution tarballs') {
      steps {
        script {
          INFRAPOOL_EXECUTORV2_AGENT_0.agentSh './bin/package.sh'
          INFRAPOOL_EXECUTORV2_AGENT_0.agentArchiveArtifacts artifacts: 'output/dist/*', fingerprint: true
        }
      }
    }
  }

  post {
    always {
      releaseInfraPoolAgent(".infrapool/release_agents")
    }
  }
}
