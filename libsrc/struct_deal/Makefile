FLAGS= -g -o
CFLAGS= -g -c -fPIC -DUSER_MODE 
CC=gcc
LD=ld
CCP=g++
STRUCTOBJ= struct_deal.o radix64.o struct_json.o

main: ../lib/libstruct.a  ../lib/libstruct.so test_main
test_main: test_main.c ../lib/libstruct.a 
	$(CC) $(FLAGS) test_main test_main.c -L../lib -lstruct  
../lib/libstruct.so:$(STRUCTOBJ)
	gcc -shared -o libstruct.so $(STRUCTOBJ)
	mv   libstruct.so ../lib
../lib/libstruct.a: $(STRUCTOBJ)
	ar rs libstruct.a $(STRUCTOBJ)
	mv libstruct.a ../lib
struct_deal.o  :  struct_deal.c ../include/struct_deal.h
	$(CC) $(CFLAGS) struct_deal.c
struct_json.o  :  struct_json.c ../include/struct_deal.h
	$(CC) $(CFLAGS) struct_json.c
radix64.o: radix64.c radix64.h
clean:
	rm -f *~ *.a *.o ../lib/libstruct.a ../lib/libstruct.so
