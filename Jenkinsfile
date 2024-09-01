pipeline {
    agent any

    environment {
        DEFECTDOJO_URL = 'http://localhost:8081'
        DEFECTDOJO_API_KEY = 'Token 8c242caae0c31ccdb9d3667e0befe055dad34bc5'
        SCAN_DIR = '/home/kali'
        GIT_HTTP_POSTBUFFER = '524288000'
        USER_BIN = '/home/jenkinsinstrument'
    }

    stages {
         stage('Install Tools') {
            steps {
                script {

                    /*// Устанавливаем CodeQL
                    sh '''
                    wget https://github.com/github/codeql-cli-binaries/releases/download/v2.18.3/codeql-linux64.zip -O codeql.zip
                    unzip codeql.zip -d ${USER_BIN}
                    rm codeql.zip
                    '''

                    // Устанавливаем Semgrep
                    sh '''
                    wget https://github.com/semgrep/semgrep/archive/refs/tags/v1.85.0.tar.gz -O semgrep.tar.gz
                    tar -xzf semgrep.tar.gz -C ${USER_BIN}
                    rm semgrep.tar.gz
                    '''

                    // Устанавливаем Njsscan
                    sh 'pip install njsscan'

                    // Устанавливаем cdxgen
                    sh '''
                    wget https://github.com/CycloneDX/cdxgen/releases/download/v10.9.5/cdxgen-dist.zip -O cdxgen.zip
                    unzip cdxgen.zip -d {USER_BIN}
                    rm cdxgen.zip
                    '''

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
                    wget https://github.com/zaproxy/zaproxy/releases/download/v2.15.0/ZAP_2.15.0_Linux.tar.gz -O zap.tar.gz
                    tar -xzf zap.tar.gz -C ${USER_BIN}
                    rm zap.tar.gz
                    '''

                    // Устанавливаем Gitleaks
                    sh '''
                    wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz -O gitleaks.tar.gz
                    tar -xzf gitleaks.tar.gz -C ${USER_BIN}
                    rm gitleaks.tar.gz
                    '''

                    // Устанавливаем Kics (Checkov)
                    sh '''
                    wget https://github.com/bridgecrewio/checkov/releases/download/3.2.239/checkov_linux_X86_64.zip -O kics.zip
                    unzip kics.zip -d ${USER_BIN}
                    rm kics.zip
                    '''*/

                    sh 'chmod -R +x ${USER_BIN}'

                }
            }
        }

        stage('SAST') {
            parallel {
                stage('CodeQL') {
                    steps {
                        script {
                            // sh '${USER_BIN}/codeql/codeql database create codeql-db --language=javascript --source-root=${SCAN_DIR}'
                            sh '${USER_BIN}codeql/codeql database analyze /path/to/database --format=sarifv2.1.0 --output=/path/to/output/codeql-results.sarif'
                        }
                    }
                }

                stage('Semgrep') {
                    steps {
                        script {
                            sh '${USER_BIN}/semgrep-1.85.0 --config="auto" ${SCAN_DIR} --output=semgrep-results.json'
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
