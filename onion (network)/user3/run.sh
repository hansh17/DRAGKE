docker build -t user3 .
docker rm -f dv_user3
docker run -d --name dv_user3 user3
docker exec -it dv_user3 /bin/bash
