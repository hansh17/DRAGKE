FROM ubuntu:16.04

RUN apt update && apt -y upgrade
RUN apt install -y netcat

ENV USER user3

#Copy Binary
ADD safetalk /root/safetalk
ADD *.pub /root/
ADD $USER.priv /root/$USER.priv
ADD loop.sh /loop.sh

#Copy GPG keys.
ADD ./.gnupg /root/.gnupg

#Set Priviledge
RUN chmod 777 /root

#start
WORKDIR /root/
CMD ["/loop.sh"]
