// Pipeline DevSecOps - SecureDev (OCY1102 EV3)
// Etapas: Checkout -> Dependency Management -> Build -> Test -> Analyze (SAST)
//         -> Generate Documentation -> Deploy -> Security Test (OWASP ZAP) -> Trazabilidad
// Las etapas de seguridad marcan el build como UNSTABLE (amarillo) si encuentran
// vulnerabilidades, para que el pipeline siga y genere todos los reportes.

pipeline {
    agent any

    options {
        buildDiscarder(logRotator(numToKeepStr: '20'))
    }

    environment {
        IMAGE                     = 'securedev-app'
        APP_CONTAINER             = 'app'
        NETWORK                   = 'devsecops'
        PIPENV_VENV_IN_PROJECT    = '1'
        PIPENV_YES                = '1'
        PIPENV_NOSPIN             = '1'
        PIPENV_IGNORE_VIRTUALENVS = '1'
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
                sh 'rm -rf reports docs && mkdir -p reports'
                sh 'git log --oneline -5'
            }
        }

        stage('Dependency Management') {
            steps {
                // pipenv: resuelve y fija (lock) las versiones, crea el entorno virtual
                sh 'pipenv lock'
                sh 'pipenv install --dev'
                // requirements.txt se genera desde Pipfile.lock (única fuente de verdad)
                sh 'pipenv requirements > requirements.txt'
                sh 'cp Pipfile.lock requirements.txt reports/'
                sh 'pipenv graph > reports/arbol-dependencias.txt'
                sh 'pipenv run pip list --outdated > reports/dependencias-desactualizadas.txt || true'
                // pip-audit: busca CVE conocidos en las dependencias
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh '''
                        set +e
                        pip-audit -r requirements.txt --desc -f markdown -o reports/pip-audit.md
                        rc=$?
                        cat reports/pip-audit.md
                        exit $rc
                    '''
                }
            }
        }

        stage('Build') {
            steps {
                sh 'pipenv run python -m py_compile app.py'
                sh 'docker build -t $IMAGE:$BUILD_NUMBER -t $IMAGE:latest .'
            }
        }

        stage('Test') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh 'pipenv run python -m pytest -v --junitxml=reports/junit.xml'
                }
            }
            post {
                always { junit allowEmptyResults: true, testResults: 'reports/junit.xml' }
            }
        }

        stage('Analyze (SAST - Bandit)') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh '''
                        set +e
                        bandit app.py -f html -o reports/bandit.html
                        bandit app.py -f txt -o reports/bandit.txt
                        rc=$?
                        cat reports/bandit.txt
                        exit $rc
                    '''
                }
            }
        }

        stage('Generate Documentation') {
            steps {
                sh 'doxygen Doxyfile'
                sh 'ls docs/html | head'
            }
        }

        stage('Deploy') {
            steps {
                sh '''
                    docker rm -f $APP_CONTAINER || true
                    docker run -d --name $APP_CONTAINER --network $NETWORK -p 5000:5000 \
                        --restart unless-stopped $IMAGE:$BUILD_NUMBER
                    for i in $(seq 1 30); do
                        curl -fs http://$APP_CONTAINER:5000/ > /dev/null && echo "App desplegada OK" && exit 0
                        sleep 2
                    done
                    echo "La app no respondió" && exit 1
                '''
            }
        }

        stage('Security Test (DAST - OWASP ZAP)') {
            steps {
                sh '''
                    docker rm -f zap || true
                    docker volume rm -f zap-wrk || true
                    docker volume create zap-wrk
                    docker run --rm -v zap-wrk:/zap/wrk alpine chmod 777 /zap/wrk
                    docker run --name zap --network $NETWORK -v zap-wrk:/zap/wrk zaproxy/zap-stable \
                        zap-full-scan.py -t http://$APP_CONTAINER:5000 -m 1 \
                        -r zap-report.html -J zap-report.json -w zap-report.md -I || true
                    docker cp zap:/zap/wrk/zap-report.html reports/ || true
                    docker cp zap:/zap/wrk/zap-report.json reports/ || true
                    docker cp zap:/zap/wrk/zap-report.md reports/ || true
                    docker rm -f zap || true
                '''
                // Marca UNSTABLE si ZAP encontró alertas de riesgo Alto (riskcode 3) o Medio (2)
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh '''
                        test -f reports/zap-report.json || { echo "No se generó el reporte de ZAP"; exit 1; }
                        python3 - <<'EOF'
import json, sys
data = json.load(open("reports/zap-report.json"))
alertas = [a for s in data.get("site", []) for a in s.get("alerts", [])]
riesgo = {"3": "ALTO", "2": "MEDIO", "1": "BAJO", "0": "INFO"}
for a in sorted(alertas, key=lambda a: -int(a["riskcode"])):
    print(f"[{riesgo[a['riskcode']]}] {a['name']} (instancias: {a.get('count', '?')})")
graves = [a for a in alertas if a["riskcode"] in ("2", "3")]
print(f"\\nTotal alertas: {len(alertas)} | Alto/Medio: {len(graves)}")
sys.exit(1 if graves else 0)
EOF
                    '''
                }
            }
        }

        stage('Trazabilidad') {
            steps {
                sh '''
                    {
                      echo "# Registro de trazabilidad - Build #$BUILD_NUMBER"
                      echo ""
                      echo "- Job: $JOB_NAME"
                      echo "- URL del build: $BUILD_URL"
                      echo "- Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
                      echo "- Commit: $(git rev-parse HEAD)"
                      echo "- Autor del commit: $(git log -1 --pretty='%an <%ae>')"
                      echo "- Mensaje: $(git log -1 --pretty='%s')"
                      echo "- Imagen desplegada: $IMAGE:$BUILD_NUMBER ($(docker image inspect $IMAGE:$BUILD_NUMBER --format '{{.Id}}'))"
                      echo ""
                      echo "## Últimos commits"
                      git log --pretty='- %h %ad %an: %s' --date=short -10
                      echo ""
                      echo "## Versiones de herramientas"
                      echo "- $(python3 --version)"
                      echo "- pipenv $(pipenv --version | awk '{print $NF}')"
                      echo "- $(pip-audit --version)"
                      echo "- $(bandit --version | head -1)"
                      echo "- doxygen $(doxygen --version)"
                      echo "- $(docker --version)"
                      echo ""
                      echo "## Reportes generados (SHA-256)"
                      cd reports && sha256sum * | sed 's/^/- /'
                    } > reports/trazabilidad.md
                    cat reports/trazabilidad.md
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/**, docs/html/**', fingerprint: true, allowEmptyArchive: true
        }
        success  { echo 'Pipeline OK: sin hallazgos de seguridad bloqueantes.' }
        unstable { echo 'Pipeline UNSTABLE: revisar reportes de seguridad en Artefactos.' }
        failure  { echo 'Pipeline FALLÓ: revisar la consola.' }
    }
}
