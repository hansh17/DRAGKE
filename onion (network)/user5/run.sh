docker build -t user5 .
docker rm -f dv_user5
docker run -d --name dv_user5 user5
docker exec -it dv_user5 /bin/bash
