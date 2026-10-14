pipeline {
  agent any
  environment {
    IMAGE = 'healthcare-app:v1'
  }
  stages {
    stage('SAST - SonarQube') {
      steps {
        withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
          sh '''
            docker run --rm --network host \
              -e SONAR_HOST_URL=http://localhost:9000 \
              -e SONAR_TOKEN \
              -v "$WORKSPACE:/usr/src" \
              sonarsource/sonar-scanner-cli \
              -Dsonar.working.directory=/tmp/scannerwork
          '''
        }
      }
    }
    stage('Build Secure Image') {
      steps { sh 'docker build -t $IMAGE .' }
    }
    stage('Container Scan - Trivy') {
      steps {
        sh '''
          docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v trivy-cache:/root/.cache/ \
            aquasec/trivy:0.58.1 image --scanners vuln --severity HIGH,CRITICAL --exit-code 0 $IMAGE
        '''
      }
    }
    stage('Deploy to Kubernetes') {
      steps {
        sh '''
          sudo -H -u ubuntu /usr/local/bin/minikube image load $IMAGE
          kubectl apply -f rbac.yaml
          kubectl apply -f deployment.yaml
          kubectl rollout restart deployment/healthcare-app
          kubectl rollout status deployment/healthcare-app --timeout=180s
        '''
      }
    }
    stage('DAST - OWASP ZAP') {
      steps {
        sh '''
          mkdir -p zap && chmod 777 zap
          docker run --rm --network host -v "$WORKSPACE/zap:/zap/wrk:rw" zaproxy/zap-stable \
            zap-baseline.py -t http://localhost:8081 -r zap_report.html -I || true
        '''
      }
    }
  }
  post {
    always {
      archiveArtifacts artifacts: 'zap/zap_report.html', allowEmptyArchive: true
    }
  }
}
