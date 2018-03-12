//"Jenkins Pipeline is a suite of plugins which supports implementing and integrating continuous delivery pipelines into Jenkins. Pipeline provides an extensible set of tools for modeling delivery pipelines "as code" via the Pipeline DSL."
//More information can be found on the Jenkins Documentation page https://jenkins.io/doc/
pipeline {
    agent { label 'linux-large' }
    options {
        buildDiscarder(logRotator(numToKeepStr:'25'))
        disableConcurrentBuilds()
        timestamps()
        skipDefaultCheckout()
    }
    triggers {
        cron(BRANCH_NAME == "master" ? "H H(17-19) * * *" : "")
    }
    environment {
        PATH="${tool 'docker-latest'}/bin:$PATH"
    }
    stages {
        stage('Setup') {
            steps {
                slackSend color: 'good', message: "STARTED: ${JOB_NAME} ${BUILD_NUMBER} ${BUILD_URL}"
            }
        }
        stage('Full Build') {
            parallel {
                stage ('Linux') {
                    steps {
                        timeout(time: 3, unit: 'HOURS') {
                            withMaven(maven: 'Maven 3.3.9', globalMavenSettingsConfig: 'default-global-settings', mavenSettingsConfig: 'codice-maven-settings', mavenOpts: '${LARGE_MVN_OPTS} ${LINUX_MVN_RANDOM}') {
                                sh 'mvn clean install -P docker'
                            }
                        }
                    }
                }
                stage ('Windows') {
                    agent { label 'server-2016-large'}
                    steps {
                        retry(3) {
                            checkout scm
                        }
                        timeout(time: 3, unit: 'HOURS') {
                            withMaven(maven: 'M35', jdk: 'jdk8-latest', globalMavenSettingsConfig: 'default-global-settings', mavenSettingsConfig: 'codice-maven-settings', mavenOpts: '${LARGE_MVN_OPTS}') {
                                bat 'mvn clean install -P docker'
                            }
                        }
                    }
                }
            }
        }
        stage('Security Analysis') {

        }
        stage('Deploy') {
            when {
                allOf {
                    expression { env.CHANGE_ID == null }
                    expression { env.BRANCH_NAME == "master" }
                }
            }
            environment {
                DOCKER_LOGIN = credentials('dockerhub-codicebot')
            }
            steps {
                sh 'docker login -u $DOCKER_LOGIN_USR -p $DOCKER_LOGIN_PSW'
                sh 'docker push codice/samlconf'
            }
        }
        stage('Run Tests') {
            steps {
                sh 'cd distribution/docker'
                sh 'docker-compose up'
            }
        }
    }
    post {
        success {
            slackSend color: 'good', message: "SUCCESS: ${JOB_NAME} ${BUILD_NUMBER}"
        }
        failure {
            slackSend color: '#ea0017', message: "FAILURE: ${JOB_NAME} ${BUILD_NUMBER}. See the results here: ${BUILD_URL}"
        }
        unstable {
            slackSend color: '#ffb600', message: "UNSTABLE: ${JOB_NAME} ${BUILD_NUMBER}. See the results here: ${BUILD_URL}"
        }
    }
}