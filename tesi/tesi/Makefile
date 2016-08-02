FLAGS= -g -o 
LIBFLAGS = -g -shared -o
INCLUDE= -I$(CUBELIBPATH)/include/ 
CFLAGS= -g -c -fPIC -DUSER_MODE $(INCLUDE)
CC=gcc
CCP=g++
FUNCOBJ= common.o tesi_certs.o key_certify.o
TEST_LIB= -L$(CUBELIBPATH)/lib -lstruct -lcrypto_func 

main: $(CUBELIBPATH)/lib/libtesi.a $(CUBELIBPATH)/lib/libtesi.so
$(CUBELIBPATH)/lib/libtesi.so: $(FUNCOBJ)	
	gcc -shared -o libtesi.so $(FUNCOBJ)
	mv libtesi.so $(CUBELIBPATH)/lib 
$(CUBELIBPATH)/lib/libtesi.a: $(FUNCOBJ)	
	ar cr libtesi.a $(FUNCOBJ) 
	cp libtesi.a $(CUBELIBPATH)/lib
common.o: common.c common.h
	$(CC) $(CFLAGS) common.c
tesi_certs.o: tesi_certs.c 
	$(CC) $(CFLAGS) tesi_certs.c
key_certify.o: key_certify.c 
	$(CC) $(CFLAGS) key_certify.c
clean:
	rm -f *~ *.o *.a
