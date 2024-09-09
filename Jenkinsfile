pipeline {
    agent any

    environment {
        CODEQL_DIR = "${WORKSPACE}/codeql"
        TOOLS_DIR = "${WORKSPACE}/tools"
        DEFECTDOJO_URL = 'http://localhost:8081'
        DEFECTDOJO_API_KEY = 'Token 8c242caae0c31ccdb9d3667e0befe055dad34bc5'
        DEPENDENCY_TRACK_API_KEY = 'odt_vxkDaeowHl9KC1CmcL11C1GNCS0QjS2U'
        DEPENDENCY_TRACK_URL = 'http://localhost:8080'
        SCAN_DIR = '/home/kali'
        GIT_HTTP_POSTBUFFER = '524288000'
        USER_DATA = '/home/jenkinsinstrument/databaza'
        RESULTS = '/var/lib/jenkins/workspace/BrokenCrystals/results'
        DATABASE = '/var/lib/jenkins/workspace/BrokenCrystals/database'
        JENKWORK = '/var/lib/jenkins/workspace/BrokenCrystals'
    }

    stages {
        stage('Prepare Git') {
            steps {
                sh 'git config --global http.postBuffer ${GIT_HTTP_POSTBUFFER}' 
                sh 'git config --global http.version HTTP/1.1'                   
            }
        }

        stage('Checkout') {
            steps {
                checkout scm  
            }
        }
         /*stage('Install Dependencies') {
            steps {
                // Создаем директорию
                sh '''
                mkdir -p ${TOOLS_DIR}
                '''
                // Устанавливаем CodeQL
                sh '''
                    curl -L https://github.com/github/codeql-cli-binaries/releases/download/v2.18.3/codeql-linux64.zip -o codeql.zip
                    unzip codeql.zip -d ${CODEQL_DIR}
                    export PATH=$PATH:${CODEQL_DIR}/codeql
                ''' 
                // Устанавливаем Semgrep
                sh '''
                    pip3 install semgrep
                '''
                // Устанавливаем Njsscan
                sh '''
                    pip install njsscan
                '''
                // Устанавливаем cdxgen
                sh '''
                    curl -L https://github.com/CycloneDX/cdxgen/releases/download/v10.9.6/cdxgen-dist.zip -o cdxgen.zip
                    unzip cdxgen.zip -d ${TOOLS_DIR}
                    chmod +x ${TOOLS_DIR}/cdxgen-latest-x86_64.AppImage
                '''
                // Устанавливаем Trivy
                sh '''
                    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/scripts/install.sh | sh -s -- -b ${TOOLS_DIR}
                '''
                // Устанавливаем Nuclei
                sh '''
                    curl -L https://github.com/projectdiscovery/nuclei/releases/download/v2.7.4/nuclei_2.7.4_linux_amd64.zip -o nuclei.zip
                    unzip nuclei.zip -d ${TOOLS_DIR}
                    chmod +x ${TOOLS_DIR}/nuclei
                '''
                // Устанавливаем OWASP ZAP
                sh '''
                    curl -L https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2_14_0_unix.sh -o zap.sh
                    chmod +x zap.sh
                    ./zap.sh -q
                '''
                // Устанавливаем Gitleaks
                sh '''
                    curl -L https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz -O gitleaks.tar.gz
                    tar -xzf gitleaks.tar.gz -C ${TOOLS_DIR}
                    rm gitleaks.tar.gz
                    chmod +x ${TOOLS_DIR}/gitleaks
                '''
                // Устанавливаем Kics
                sh '''
                    curl -L https://github.com/bridgecrewio/checkov/releases/download/3.2.239/checkov_linux_X86_64.zip -O kics.zip
                    unzip kics.zip -d ${TOOLS_DIR}
                    rm kics.zip
                    chmod +x ${TOOLS_DIR}/kics
                '''
            }
        } */

        /*stage('SAST: CodeQL') {
            steps {
                sh '''
                    ${CODEQL_DIR}/codeql/codeql database create ${DATABASE}/codeql-db --language=javascript --source-root=${SCAN_DIR} --overwrite
                    ${CODEQL_DIR}/codeql/codeql database analyze ${DATABASE}/codeql-db --format=sarif-latest --output=${RESULTS}/codeql-results.sarif
                '''
            }
        } */

        /*stage('SAST: Semgrep') {
            steps {
                sh '''
                    semgrep scan --config=auto
                '''

            }
        }

        stage('SAST: Njsscan') {
            steps {
                sh '''
                    njsscan ${JENKWORK}/zap.sh --output ${RESULTS}
                '''
            }
        }

        stage('OSA: cdxgen') {
            steps {
                sh '''
                    cdxgen -r -o ${RESULTS}/bom-cdxgen.json 
                '''
            }
        }

        stage('OSA: Trivy') {
            steps {
                sh '''
                    trivy fs --format json --output ${RESULTS}/bom-trivy.json ${JENKWORK}/tools
                '''
            }
        }
        stage('Upload SBOM to Dependency Track') {
            steps {
                sh '''
                     curl -X "POST" "http://localhost:8080/api/v1/bom" \
                        -H 'Content-Type: application/json' \
                        -H "X-API-Key: ${DEPENDENCY_TRACK_API_KEY}" \
                        -d @- << 'EOF'
                       {
                        "project": "f90934f5-cb88-47ce-81cb-db06fc67d4b4",
                        "bom": $(cat ${RESULTS}/bom-cdxgen.json)
                       }
                        EOF
                '''
                // Загрузка SBOM trivy
                sh '''
                     curl -X "POST" "http://localhost:8080/api/v1/bom" \
                        -H 'Content-Type: application/json' \
                        -H "X-API-Key: ${DEPENDENCY_TRACK_API_KEY}" \
                        -d @- << 'EOF'
                       {
                        "project": "f90934f5-cb88-47ce-81cb-db06fc67d4b4",
                        "bom": $(cat ${RESULTS}/bom-trivy.json)
                       }
                        EOF
                '''
            }
        }

        stage('DAST: Nuclei') {
            steps {
                sh '''
                    nuclei -u https://brokencrystals.com/ --output ${RESULTS}/nuclei-results.txt
                '''
            }
        }

        stage('DAST: ZAP') {
            steps {
                sh '''
                    ${JENKWORK}./zap.sh -daemon -config api.disablekey=true
                    zap-cli quick-scan --self-contained --start-options '-config api.disablekey=true' -r ${RESULTS}/zap-report.html
                '''
            }
        }

        stage('Secrets: Gitleaks') {
            steps {
                sh '''
                    gitleaks detect --source=${JENKWORK} --report=${RESULTS}/gitleaks-report.json
                '''
            }
        }

        stage('IAC: Kics') {
            steps {
                sh '''
                    checkov -d ${JENKWORK} --output-file-path ${RESULTS}/kics-results.json
                '''
            }
        }*/

        stage('Send Results to DefectDojo') {
            steps {
                
                    /*curl -X POST -H "Authorization: ApiKey ${DEFECT_DOJO_API_KEY}" -F 'scan_type=CodeQL' -F 'file=@${RESULTS}/codeql-results.sarif' ${DEFECT_DOJO_URL}/api/v2/import-scan/
                    curl -X POST -H "Authorization: ApiKey ${DEFECT_DOJO_API_KEY}" -F 'scan_type=Semgrep' -F 'file=@${RESULTS}/semgrep-results.json' ${DEFECT_DOJO_URL}/api/v2/import-scan/
                    curl -X POST -H "Authorization: ApiKey ${DEFECT_DOJO_API_KEY}" -F 'scan_type=Njsscan' -F 'file=@${RESULTS}/njsscan-results.json' ${DEFECT_DOJO_URL}/api/v2/import-scan/
                    curl -X POST -H "Authorization: ApiKey ${DEFECT_DOJO_API_KEY}" -F 'scan_type=Nuclei' -F 'file=${RESULTS}/nuclei-results.txt' ${DEFECT_DOJO_URL}/api/v2/import-scan/
                    curl -X POST -H "Authorization: ApiKey ${DEFECT_DOJO_API_KEY}" -F 'scan_type=ZAP Scan' -F 'file=${RESULTS}/zap-report.html' ${DEFECT_DOJO_URL}/api/v2/import-scan/
                    curl -X POST -H "Authorization: ApiKey ${DEFECT_DOJO_API_KEY}" -F 'scan_type=Gitleaks' -F 'file=${RESULTS}/gitleaks-report.json' ${DEFECT_DOJO_URL}/api/v2/import-scan/
                    curl -X POST -H "Authorization: ApiKey ${DEFECT_DOJO_API_KEY}" -F 'scan_type=KICS' -F 'file=${RESULTS}/kics-results.json' ${DEFECT_DOJO_URL}/api/v2/import-scan/*/
                  sh '''
                    curl -X 'POST' \
                    'http://localhost:8081/api/v2/import-scan/' \
                    -H 'accept: application/json' \
                    -H 'Content-Type: multipart/form-data' \
                    -H 'Authorization: Token 8c242caae0c31ccdb9d3667e0befe055dad34bc5' \
                    -F 'files=@/var/lib/jenkins/workspace/BrokenCrystals/results/nuclei-results.json' \
                    -F 'scan_type=Nuclei'
                    '''
            }
        }
    }
}
