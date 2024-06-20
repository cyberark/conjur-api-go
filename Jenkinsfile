#!/usr/bin/env groovy
@Library("product-pipelines-shared-library") _

// Automated release, promotion and dependencies
properties([
  // Include the automated release parameters for the build
  release.addParams(),
  // Dependencies of the project that should trigger builds
  dependencies([])
])

// Performs release promotion.  No other stages will be run
if (params.MODE == "PROMOTE") {
  release.promote(params.VERSION_TO_PROMOTE) { sourceVersion, targetVersion, assetDirectory ->

  }
  // Copy Github Enterprise release to Github
  release.copyEnterpriseRelease(params.VERSION_TO_PROMOTE)
  return
}

pipeline {
  agent { label 'conjur-enterprise-common-agent' }

  options {
    timestamps()
    buildDiscarder(logRotator(numToKeepStr: '30'))
  }

  triggers {
    cron(getDailyCronString())
  }

  environment {
    // Sets the MODE to the specified or autocalculated value as appropriate
    MODE = release.canonicalizeMode()
  }

  stages {
    // Aborts any builds triggered by another project that wouldn't include any changes
    stage ("Skip build if triggering job didn't create a release") {
      when {
        expression {
          MODE == "SKIP"
        }
      }
      steps {
        script {
          currentBuild.result = 'ABORTED'
          error("Aborting build because this build was triggered from upstream, but no release was built")
        }
      }
    }
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
          INFRAPOOL_EXECUTORV2_AGENTS = getInfraPoolAgent(type: "ExecutorV2", quantity: 1, duration: 1)
          INFRAPOOL_EXECUTORV2_AGENT_0 = INFRAPOOL_EXECUTORV2_AGENTS[0]
          infrapool = infraPoolConnect(INFRAPOOL_EXECUTORV2_AGENT_0, {})
        }
      }
    }

    // Generates a VERSION file based on the current build number and latest version in CHANGELOG.md
    stage('Validate Changelog and set version') {
      steps {
        script {
          updateVersion(infrapool, "CHANGELOG.md", "${BUILD_NUMBER}")
        }
      }
    }

    stage('Run Tests') {
      environment {
        // Currently, we're not updating DockerHub during version releases/promotions, which we need to fix.
        // Added a switch in Jenkinsfile and test configurations to toggle between registry.tld for internal testing and docker.io for using the conjur:edge image externally. 
        // Tests default to using DockerHub images. In our internal Jenkins setup, this is overridden to pull from our internal registry instead.
        REGISTRY_URL = "registry.tld"
      }
      parallel {
        stage('Golang 1.22') {
          steps {
            script {
              infrapool.agentSh "./bin/test.sh 1.22 $REGISTRY_URL"
              infrapool.agentStash name: '1.22-out', includes: 'output/1.22/*.xml'
              unstash '1.22-out'
            }
          }
        }

        stage('Golang 1.21') {
          steps {
            script {
              infrapool.agentSh "./bin/test.sh 1.21 $REGISTRY_URL"
              infrapool.agentStash name: '1.21-out', includes: 'output/1.21/*.xml'
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
              infrapool.agentSh 'cp output/1.21/c.out .'
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
          infrapool.agentSh './bin/package.sh'
          infrapool.agentArchiveArtifacts artifacts: 'output/dist/*', fingerprint: true
        }
      }
    }

    stage('Release') {
      when {
        expression {
          MODE == "RELEASE"
        }
      }
      steps {
        script {
          release(infrapool) { billOfMaterialsDirectory, assetDirectory, toolsDirectory ->
            // Publish release artifacts to all the appropriate locations

            // Copy any artifacts to assetDirectory to attach them to the Github release
            infrapool.agentSh "cp -r output/dist/* ${assetDirectory}"

            // Create Go module SBOM
            infrapool.agentSh """export PATH="${toolsDirectory}/bin:${PATH}" && go-bom --tools "${toolsDirectory}" --go-mod ./go.mod --image "golang" --output "${billOfMaterialsDirectory}/go-mod-bom.json" """
          }
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
