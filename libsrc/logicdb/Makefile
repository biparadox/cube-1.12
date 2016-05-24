FLAGS= -g -o
CFLAGS= -g -c -DUSER_MODE 
CC=gcc
LD=ld
CCP=g++
LOGICOBJ= logic_baselib.o logic_compare.o logic_audit.o

main: test_main ../lib/liblogicdb.a
	rm -f *~ *.a *.o
test_main: test_main.c ../lib/liblogicdb.a
	$(CC) $(FLAGS) test_main test_main.c -L../lib -llogicdb -lstruct -lcrypto_func
../lib/liblogicdb.a:  $(LOGICOBJ)
	ar rs liblogicdb.a $(LOGICOBJ) 
	mv    liblogicdb.a ../lib
logic_baselib.o: logic_baselib.c ../include/logic_baselib.h 	
	$(CC) $(CFLAGS) logic_baselib.c
#logic_audit.o: logic_audit.c 
#	$(CC) $(CFLAGS) logic_audit.c
logic_compare.o: logic_compare.c logic_compare.h	
	$(CC) $(CFLAGS) logic_compare.c
clean:
	rm -f *~ *.a *.o ../lib/*.a
