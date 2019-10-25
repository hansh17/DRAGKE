docker build -t user4 .
docker rm -f dv_user4
docker run -d --name dv_user4 user4
docker exec -it dv_user4 /bin/bash
