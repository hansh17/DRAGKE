all:
	gcc -o dbserver dbserver.c security.c 
	gcc -o safetalk dvonion.c route.c key_manager.c msg_encrypt.c security.c -lpthread -lncurses
	#copy public key
	cp -rf /home/user1/.gnupg ../user1/
	cp -rf /home/user2/.gnupg ../user2/
	cp -rf /home/user3/.gnupg ../user3/
	cp -rf /home/user4/.gnupg ../user4/
	cp -rf /home/user5/.gnupg ../user5/
	
	cp /home/user1/user1.priv ../user1/
	cp /home/user2/user2.priv ../user2/
	cp /home/user3/user3.priv ../user3/
	cp /home/user4/user4.priv ../user4/
	cp /home/user5/user5.priv ../user5/
	
	cp ./TESTKEY/*.pub ../user1/
	cp ./TESTKEY/*.pub ../user2/
	cp ./TESTKEY/*.pub ../user3/
	cp ./TESTKEY/*.pub ../user4/
	cp ./TESTKEY/*.pub ../user5/
	
	cp safetalk ../user1/
	cp safetalk ../user2/
	cp safetalk ../user3/
	cp safetalk ../user4/
	cp safetalk ../user5/
	#copy private key
	#gpgfile permission setting
	chmod 777 ../user1/*
	chmod 777 ../user2/*
	chmod 777 ../user3/*
	chmod 777 ../user4/*
	chmod 777 ../user5/*
	chmod 777 .
	echo "----------end of file------------" > OnionUser.db # initialization db file
	
	
	
	
	
