FLAGS= -g -o 
CFLAGS= -g -c -DUSER_MODE 
CC=gcc
CCP=g++
STRUCTOBJ= cube_cafunc.o

main: test_main  
test_main: test_main.c cube_cafunc.o
	$(CC) $(FLAGS) test_main test_main.c $(STRUCTOBJ) -L/usr/local/lib -L../../lib -ltesi -ltspi -lcrypto -lstruct -lcrypto_func
cube_cafunc.o  :  cube_cafunc.c cube_cafunc.h

	$(CC) $(CFLAGS) cube_cafunc.c
clean:
	rm -f test_main *~ *.o *.a
