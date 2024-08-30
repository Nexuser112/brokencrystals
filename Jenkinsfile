pipeline {
    agent any

    environment {
        DEFECTDOJO_URL = 'http://localhost:8081'
        DEFECTDOJO_API_KEY = 'Token 8c242caae0c31ccdb9d3667e0befe055dad34bc5'
        SCAN_DIR = '/home/kali'
        GIT_HTTP_POSTBUFFER = '524288000'
    }

    stages {
        stage('Install Tools') {
            steps {
                script {
                    // Установка CodeQL
                    sh 'curl -sSL https://github.com/github/codeql-cli-binaries/releases/download/v2.12.0/codeql-linux64.zip -o codeql.zip'
                    sh 'unzip codeql.zip -d /usr/local/bin'
                    
                    // Установка Semgrep
                    sh 'pip install semgrep'
                    
                    // Установка Njsscan
                    sh 'npm install -g njsscan'
                    
                    // Установка Cdxgen
                    sh 'npm install -g @snyk/cdxgen'
                    
                    // Установка Trivy
                    sh 'curl -sSL https://github.com/aquasecurity/trivy/releases/download/v0.31.2/trivy_0.31.2_Linux-64bit.tar.gz -o trivy.tar.gz'
                    sh 'tar xzf trivy.tar.gz -C /usr/local/bin'
                    
                    // Установка Nuclei
                    sh 'curl -sSL https://github.com/projectdiscovery/nuclei/releases/download/v2.6.7/nuclei_2.6.7_linux_amd64.tar.gz -o nuclei.tar.gz'
                    sh 'tar xzf nuclei.tar.gz -C /usr/local/bin'
                    
                    // Установка Zap
                    sh 'curl -sSL https://github.com/zaproxy/zaproxy/releases/download/v2.12.0/ZAP_2.12.0_Linux.tar.gz -o zap.tar.gz'
                    sh 'tar xzf zap.tar.gz -C /usr/local/bin'
                    
                    // Установка Gitleaks
                    sh 'curl -sSL https://github.com/gitleaks/gitleaks/releases/download/v8.13.0/gitleaks-linux-amd64 -o /usr/local/bin/gitleaks'
                    sh 'chmod +x /usr/local/bin/gitleaks'
                    
                    // Установка Kics
                    sh 'curl -sSL https://github.com/Checkmarx/kics/releases/download/v1.6.1/kics_1.6.1_Linux_x86_64.tar.gz -o kics.tar.gz'
                    sh 'tar xzf kics.tar.gz -C /usr/local/bin'

                }
            }
        }

        stage('SAST') {
            parallel {
                stage('CodeQL') {
                    steps {
                        script {
                            sh 'codeql database create codeql-db --language=javascript --source-root=${SCAN_DIR}'
                            sh 'codeql analyze codeql-db --format=sarifv2.1.0 --output=codeql-results.sarif'
                        }
                    }
                }

                stage('Semgrep') {
                    steps {
                        script {
                            sh 'semgrep --config="auto" ${SCAN_DIR} --output=semgrep-results.json'
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
                            sh 'cdxgen -o sbom.json -d ${SCAN_DIR}'
                        }
                    }
                }

                stage('Trivy') {
                    steps {
                        script {
                            sh 'trivy fs ${SCAN_DIR} --format json --output trivy-results.json'
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
                            sh 'nuclei -target ${SCAN_DIR} -o nuclei-results.json'
                        }
                    }
                }

                stage('Zap') {
                    steps {
                        script {
                            sh 'zap-cli quick-scan ${SCAN_DIR} -o zap-results.html'
                        }
                    }
                }
            }
        }

        stage('Secrets') {
            steps {
                script {
                    sh 'gitleaks --repo-path=${SCAN_DIR} --report-format=json --report-path=gitleaks-results.json'
                }
            }
        }

        stage('IAC') {
            steps {
                script {
                    sh 'checkov -d ${SCAN_DIR} -o json > kics-results.json'
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
