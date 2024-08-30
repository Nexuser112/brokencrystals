pipeline {
    agent any

    environment {
        DEFECTDOJO_URL = 'http://localhost:8081'
        DEFECTDOJO_API_KEY = 'Token 8c242caae0c31ccdb9d3667e0befe055dad34bc5'
        SCAN_DIR = '/home/kali'
        GIT_HTTP_POSTBUFFER = '524288000'
        USER_BIN = '/tmp/bin'
    }

    stages {
        stage('Install Tools') {
            steps {
                script {
                    // Создаем директорию для установки
                    // sh 'mkdir -p ${USER_BIN}'

                    // Устанавливаем CodeQL
                    /*sh '''
                    wget https://github.com/github/codeql-cli-binaries/releases/download/v2.12.0/codeql-linux64.zip -O codeql.zip
                    unzip codeql.zip -d ${USER_BIN}
                    rm codeql.zip
                    '''*/

                    // Устанавливаем Semgrep
                    sh '''
                    wget https://github.com/semgrep/semgrep/archive/refs/tags/v1.85.0.tar.gz -O semgrep.tar.gz
                    tar -xzf semgrep.tar.gz -C ${USER_BIN}
                    rm semgrep.tar.gz
                    '''

                    // Устанавливаем Njsscan
                    sh '''
                    wget https://github.com/guard/security/releases/download/v1.0.0/njsscan-linux-x64.tar.gz -O njsscan.tar.gz
                    tar -xzf njsscan.tar.gz -C ${USER_BIN}
                    rm njsscan.tar.gz
                    '''

                    // Устанавливаем cdxgen
                    sh 'npm install -g @snyk/cdxgen --prefix ${USER_BIN}'

                    // Устанавливаем Trivy
                    sh '''
                    wget https://github.com/aquasecurity/trivy/releases/download/v0.31.2/trivy_0.31.2_Linux-64bit.tar.gz -O trivy.tar.gz
                    tar -xzf trivy.tar.gz -C ${USER_BIN}
                    rm trivy.tar.gz
                    '''

                    // Устанавливаем Nuclei
                    sh '''
                    wget https://github.com/projectdiscovery/nuclei/releases/download/v2.8.7/nuclei_2.8.7_linux_amd64.zip -O nuclei.zip
                    unzip nuclei.zip -d ${USER_BIN}
                    rm nuclei.zip
                    '''

                    // Устанавливаем Zap
                    sh '''
                    wget https://github.com/zaproxy/zap-extensions/releases/download/v2.13.0/ZAP_2.13.0_Linux.tar.gz -O zap.tar.gz
                    tar -xzf zap.tar.gz -C ${USER_BIN}
                    rm zap.tar.gz
                    '''

                    // Устанавливаем Gitleaks
                    sh '''
                    wget https://github.com/zricethezav/gitleaks/releases/download/v8.0.0/gitleaks_8.0.0_linux_x64.tar.gz -O gitleaks.tar.gz
                    tar -xzf gitleaks.tar.gz -C ${USER_BIN}
                    rm gitleaks.tar.gz
                    '''

                    // Устанавливаем Kics (Checkov)
                    sh '''
                    wget https://github.com/bridgecrewio/checkov/releases/download/v2.1.0/checkov-linux-amd64 -O ${USER_BIN}/checkov
                    chmod +x ${USER_BIN}/checkov
                    '''

                }
            }
        }

        stage('SAST') {
            parallel {
                stage('CodeQL') {
                    steps {
                        script {
                            sh '${USER_BIN}/codeql database create codeql-db --language=javascript --source-root=${SCAN_DIR}'
                            sh '${USER_BIN}/codeql analyze codeql-db --format=sarifv2.1.0 --output=codeql-results.sarif'
                        }
                    }
                }

                stage('Semgrep') {
                    steps {
                        script {
                            sh '${USER_BIN}/semgrep --config="auto" ${SCAN_DIR} --output=semgrep-results.json'
                        }
                    }
                }

                stage('Njsscan') {
                    steps {
                        script {
                            sh '${USER_BIN}/njsscan ${SCAN_DIR} -o njsscan-results.json'
                        }
                    }
                }
            }
        }
stage('OSA') {
            parallel {
                stage('Cdxgen') {
                    steps {
                        script {
                            sh '${USER_BIN}/cdxgen -o sbom.json -d ${SCAN_DIR}'
                        }
                    }
                }

                stage('Trivy') {
                    steps {
                        script {
                            sh '${USER_BIN}/trivy fs ${SCAN_DIR} --format json --output trivy-results.json'
                        }
                    }
                }
            }
        }

        stage('DAST') {
            parallel {
                stage('Nuclei') {
                    steps {
                        script {
                            sh '${USER_BIN}/nuclei -target ${SCAN_DIR} -o nuclei-results.json'
                        }
                    }
                }

                stage('Zap') {
                    steps {
                        script {
                            sh '${USER_BIN}/zap-cli quick-scan ${SCAN_DIR} -o zap-results.html'
                        }
                    }
                }
            }
        }

        stage('Secrets') {
            steps {
                script {
                    sh '${USER_BIN}/gitleaks --repo-path=${SCAN_DIR} --report-format=json --report-path=gitleaks-results.json'
                }
            }
        }

        stage('IAC') {
            steps {
                script {
                    sh '${USER_BIN}/checkov -d ${SCAN_DIR} -o json > kics-results.json'
                }
            }
        }

        stage('Upload Results to DefectDojo') {
            steps {
                script {
                    def uploadToDefectDojo = """
                        curl -X POST "${DEFECTDOJO_URL}/api/v2/import-scan/" \
                        -H "Authorization: Token ${DEFECTDOJO_API_KEY}" \
                        -F "file=@codeql-results.sarif" \
                        -F "file=@semgrep-results.json" \
                        -F "file=@njsscan-results.json" \
                        -F "file=@sbom.json" \
                        -F "file=@trivy-results.json" \
                        -F "file=@nuclei-results.json" \
                        -F "file=@zap-results.html" \
                        -F "file=@gitleaks-results.json" \
                        -F "file=@kics-results.json"
                    """
                    sh uploadToDefectDojo
                }
            }
        }
    }
}
