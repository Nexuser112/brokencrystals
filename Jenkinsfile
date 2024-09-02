pipeline {
    agent any

    environment {
        CODEQL_DIR = "${WORKSPACE}/codeql"
        DEFECTDOJO_URL = 'http://localhost:8081'
        DEFECTDOJO_API_KEY = 'Token 8c242caae0c31ccdb9d3667e0befe055dad34bc5'
        SCAN_DIR = '/home/kali'
        GIT_HTTP_POSTBUFFER = '524288000'
        USER_BIN = '/home/jenkinsinstrument'
        USER_DATA = '/home/jenkinsinstrument/databaza'
    }

    stages {
         stage('Install Dependencies') {
            steps {
                // Устанавливаем CodeQL
                sh '''
                    curl -L https://github.com/github/codeql-cli-binaries/releases/download/v2.18.3/codeql-linux64.zip -o codeql.zip
                    unzip codeql.zip -d ${CODEQL_DIR}
                    export PATH=$PATH:${CODEQL_DIR}/codeql
                '''
                // Устанавливаем Semgrep
                sh '''
                    curl -L https://github.com/returntocorp/semgrep/releases/latest/download/semgrep-linux-amd64 -o /usr/local/bin/semgrep
                    chmod +x /usr/local/bin/semgrep
                '''
                // Устанавливаем Njsscan
                sh '''
                    pip install njsscan
                '''
                // Устанавливаем cdxgen
                sh '''
                    curl -L https://github.com/CycloneDX/cdxgen/releases/latest/download/cdxgen-linux-x64 -o /usr/local/bin/cdxgen
                    chmod +x /usr/local/bin/cdxgen
                '''
                // Устанавливаем Trivy
                sh '''
                    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/scripts/install.sh | sh -s -- -b /usr/local/bin
                '''
                // Устанавливаем Nuclei
                sh '''
                    curl -L https://github.com/projectdiscovery/nuclei/releases/download/v2.7.4/nuclei_2.7.4_linux_amd64.zip -o nuclei.zip
                    unzip nuclei.zip -d /usr/local/bin
                    chmod +x /usr/local/bin/nuclei
                '''
                // Устанавливаем OWASP ZAP
                sh '''
                    curl -L https://github.com/zaproxy/zaproxy/releases/download/v2.11.1/ZAP_2_11_1_unix.sh -o zap.sh
                    chmod +x zap.sh
                    ./zap.sh -q
                '''
                // Устанавливаем Gitleaks
                sh '''
                    curl -sSfL https://raw.githubusercontent.com/gitleaks/gitleaks/main/install.sh | bash
                '''
                // Устанавливаем Kics
                sh '''
                    curl -sSfL https://github.com/Checkmarx/kics/releases/latest/download/kics-linux-amd64.tar.gz | tar -xz -C /usr/local/bin
                '''
            }
        }

        stage('SAST') {
            parallel {
                /*stage('CodeQL') {
                    steps {
                        script {
                            sh '${USER_BIN}/codeql/codeql database create ${USER_DATA} --language=javascript --source-root=${SCAN_DIR} --overwrite'
                            sh '${USER_BIN}/codeql/codeql database analyze ${USER_DATA} /home/jenkinsinstrument/codeql/javascript-queries --format=sarifv2.1.0 --output=codeql-results.sarif'
                        }
                    }
                } */

                stage('Semgrep') {
                    steps {
                        script {
                            sh '${USER_BIN}/semgrep-1.85.0 scan -o semgrep-report-fs.json'
                        }
                    }
                }

                stage('Njsscan') {
                    steps {
                        script {
                            sh 'njsscan ${SCAN_DIR} -o njsscan-results.json'
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
                            sh '${USER_BIN}/ZAP_2.15.0/zap.sh quick-scan --auto --target ${SCAN_DIR} --output zap-results.html'
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
