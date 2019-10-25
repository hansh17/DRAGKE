docker build -t user1 .
docker rm -f dv_user1
docker run -d --name dv_user1 user1
docker exec -it dv_user1 /bin/bash
