FLAGS= -g -o 
CFLAGS= -g -c -DUSER_MODE 
CC=gcc
CCP=g++
FUNCOBJ= router.o 

main: ../lib/librouter.a test
test:  test.c ../lib/librouter.a ../lib/libstruct.a 
	$(CC) $(FLAGS) test test.c -L../lib -lrouter -lmessage -llogicdb -lstruct -lcrypto_func -lpthread
../lib/librouter.a:  $(FUNCOBJ)
	ar cr librouter.a $(FUNCOBJ) 
	mv    librouter.a ../lib
router.o: router.c  
	$(CC) $(CFLAGS) router.c
clean:
	rm -f test *~ *.o *.a
