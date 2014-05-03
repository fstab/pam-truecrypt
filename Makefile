pam_truecrypt.so: pam_truecrypt.o
	gcc -shared -Xlinker -x -o pam_truecrypt.so pam_truecrypt.o 

pam_truecrypt.o: pam_truecrypt.c
	gcc -Wall -fno-strict-aliasing -O2 -c pam_truecrypt.c -o pam_truecrypt.o
