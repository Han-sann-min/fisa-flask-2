node { 
    withCredentials([[$class: 'UsernamePasswordMultiBinding', 
        credentialsId: 'docker-hub', 
        usernameVariable: 'DOCKER_USER_ID', 
        passwordVariable: 'DOCKER_USER_PASSWORD']]) 
    
    { 
     stage('Pull') {
           git branch: 'main', credentialsId: 'github-server', url: 'https://github.com/Han-sann-min/fisa-flask-2/'
        }
        

      stage('Build') {
            sh(script: '''yes | sudo docker image prune -a''')
            sh(script: '''sudo docker build -t flask_app5 .''')
        }

      stage('Tag') {
              sh(script: '''sudo docker tag flask_app5 ${DOCKER_USER_ID}/flask_app5:${BUILD_NUMBER}''') 
            }

      stage('Push') {
            sh(script: 'sudo docker login -u ${DOCKER_USER_ID} -p ${DOCKER_USER_PASSWORD}') 
            sh(script: 'sudo docker push ${DOCKER_USER_ID}/flask_app5:${BUILD_NUMBER}') 
        }
      
stage('Deploy') {
            sshagent(credentials: ['flask-ec2-server']) {
                sh(script: 'ssh  -o StrictHostKeyChecking=no ubuntu@15.164.87.34 "sudo docker rm -f docker-flask"')
                sh(script: 'ssh ubuntu@15.164.87.34 "sudo docker run --name docker-flask --env-file .env -e TZ=Asia/Seoul -p 80:80 -d -t \${DOCKER_USER_ID}/flask_app5:\${BUILD_NUMBER}"')
        }
    }

    stage('Cleaning up') { 
              sh "sudo docker rmi ${DOCKER_USER_ID}/flask_app5:${BUILD_NUMBER}" // sudo docker image 제거
      } 
    }
  }