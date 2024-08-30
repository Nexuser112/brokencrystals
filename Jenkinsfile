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
                    // Устанавливаем CodeQL
                    sh 'brew install codeql'
                    
                    // Устанавливаем Semgrep
                    sh 'brew install semgrep'
                    
                    // Устанавливаем Njsscan
                    sh 'npm install -g njsscan'
                    
                    // Устанавливаем cdxgen
                    sh 'npm install -g @snyk/cdxgen'
                    
                    // Устанавливаем Trivy
                    sh 'brew install trivy'
                    
                    // Устанавливаем Nuclei
                    sh 'brew install nuclei'
                    
                    // Устанавливаем Zap
                    sh 'brew install zap'
                    
                    // Устанавливаем Gitleaks
                    sh 'brew install gitleaks'
                    
                    // Устанавливаем Kics
                    sh 'brew install checkov'
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
