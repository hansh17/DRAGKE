docker build -t user2 .
docker rm -f dv_user2
docker run -d --name dv_user2 user2
docker exec -it dv_user2 /bin/bash
