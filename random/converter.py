f=open('tmp.txt','r');
f2=open('rlwe_table3.h','w');
i=1
while True:
	line=f.readline()
	if not line:
		break
	l=line[2:-2]
	l=l.upper()
	a=str('0x')+str('0')*(16-len(l))+l+','+' '
	f2.write(a)
	print(str(i)+"th line");
	i+=1
f.close()
f2.close()

