    pipeline {
    agent any
    environment {
        SCAN_DIR = "/home/kali"
        CODEQL_VERSION = "latest"
        DEPENDENCY_TRACK_API_KEY = credentials('dependency-track-api-key')
        DEFECT_DOJO_API_KEY = credentials('Token 8c242caae0c31ccdb9d3667e0befe055dad34bc5')
        DEFECT_DOJO_URL = 'http://localhost:8081'
    }
    stages {
        stage('Install Dependencies') {
            steps {
                // Устанавливаем CodeQL
                sh '''
                    curl -L https://github.com/github/codeql-cli-binaries/releases/download/${CODEQL_VERSION}/codeql-linux64.zip -o codeql.zip
                    unzip codeql.zip -d /opt/codeql
                    export PATH=$PATH:/opt/codeql/codeql
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

        stage('SAST: CodeQL') {
            steps {
                sh '''
                    codeql database create ${SCAN_DIR}/codeql-db --language=javascript --source-root=${SCAN_DIR}
                    codeql database analyze ${SCAN_DIR}/codeql-db --format=sarif-latest --output=${SCAN_DIR}/codeql-results.sarif
                '''
            }
        }

        stage('SAST: Semgrep') {
            steps {
                sh '''
                    semgrep --config=auto ${SCAN_DIR} --output ${SCAN_DIR}/semgrep-results.json --json
                '''
            }
        }

        stage('SAST: Njsscan') {
            steps {
                sh '''
                    njsscan ${SCAN_DIR} -o ${SCAN_DIR}/njsscan-results.json
                '''
            }
        }

        stage('OSA: cdxgen') {
            steps {
                sh '''
                    cdxgen -r -o ${SCAN_DIR}/bom-cdxgen.json ${SCAN_DIR}
                '''
            }
        }

        stage('OSA: Trivy') {
            steps {
                sh '''
                    trivy fs --format cyclonedx --output ${SCAN_DIR}/bom-trivy.json ${SCAN_DIR}
                '''
            }
        }
stage('Upload SBOM to Dependency Track') {
            steps {
                sh '''
                    curl -X POST -H "X-Api-Key: ${DEPENDENCY_TRACK_API_KEY}" -H "Content-Type: application/json" --data @${SCAN_DIR}/bom-cdxgen.json ${DEPENDENCY_TRACK_URL}/api/v1/bom
                    curl -X POST -H "X-Api-Key: ${DEPENDENCY_TRACK_API_KEY}" -H "Content-Type: application/json" --data @${SCAN_DIR}/bom-trivy.json ${DEPENDENCY_TRACK_URL}/api/v1/bom
                '''
            }
        }

        stage('DAST: Nuclei') {
            steps {
                sh '''
                    nuclei -t /nuclei-templates/ -o ${SCAN_DIR}/nuclei-results.txt
                '''
            }
        }

        stage('DAST: ZAP') {
            steps {
                sh '''
                    ./zap.sh -daemon -config api.disablekey=true
                    zap-cli quick-scan --self-contained --start-options '-config api.disablekey=true' -r ${SCAN_DIR}/zap-report.html
                '''
            }
        }

        stage('Secrets: Gitleaks') {
            steps {
                sh '''
                    gitleaks detect --source=${SCAN_DIR} --report=${SCAN_DIR}/gitleaks-report.json
                '''
            }
        }

        stage('IAC: Kics') {
            steps {
                sh '''
                    kics scan -p ${SCAN_DIR} -o ${SCAN_DIR}/kics-results.json
                '''
            }
        }

        stage('Send Results to DefectDojo') {
            steps {
                sh '''
                    curl -X POST -H "Authorization: ApiKey ${DEFECT_DOJO_API_KEY}" -F 'scan_type=CodeQL' -F 'file=@${SCAN_DIR}/codeql-results.sarif' ${DEFECT_DOJO_URL}/api/v2/import-scan/
                    curl -X POST -H "Authorization: ApiKey ${DEFECT_DOJO_API_KEY}" -F 'scan_type=Semgrep' -F 'file=@${SCAN_DIR}/semgrep-results.json' ${DEFECT_DOJO_URL}/api/v2/import-scan/
                    curl -X POST -H "Authorization: ApiKey ${DEFECT_DOJO_API_KEY}" -F 'scan_type=Njsscan' -F 'file=@${SCAN_DIR}/njsscan-results.json' ${DEFECT_DOJO_URL}/api/v2/import-scan/
                    curl -X POST -H "Authorization: ApiKey ${DEFECT_DOJO_API_KEY}" -F 'scan_type=Nuclei' -F 'file=@${SCAN_DIR}/nuclei-results.txt' ${DEFECT_DOJO_URL}/api/v2/import-scan/
                    curl -X POST -H "Authorization: ApiKey ${DEFECT_DOJO_API_KEY}" -F 'scan_type=ZAP Scan' -F 'file=@${SCAN_DIR}/zap-report.html' ${DEFECT_DOJO_URL}/api/v2/import-scan/
                    curl -X POST -H "Authorization: ApiKey ${DEFECT_DOJO_API_KEY}" -F 'scan_type=Gitleaks' -F 'file=@${SCAN_DIR}/gitleaks-report.json' ${DEFECT_DOJO_URL}/api/v2/import-scan/
                    curl -X POST -H "Authorization: ApiKey ${DEFECT_DOJO_API_KEY}" -F 'scan_type=KICS' -F 'file=@${SCAN_DIR}/kics-results.json' ${DEFECT_DOJO_URL}/api/v2/import-scan/
                '''
            }
        }
    }
    post {
        always {
            cleanWs()
        }
    }
}
