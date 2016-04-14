FLAGS= -g -o 
CFLAGS= -g -c -DUSER_MODE 
CC=gcc
CCP=g++

main: test_main  
test_main: test_main.c 
	$(CC) $(FLAGS) test_main test_main.c -L/usr/local/lib -L../../lib -ltesi -ltspi -lcrypto -lstruct -lcrypto_func
clean:
	rm -f test_main *~ *.o *.a
