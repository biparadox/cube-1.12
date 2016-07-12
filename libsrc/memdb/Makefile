FLAGS= -g -o 
CFLAGS= -g -c -fPIC -DUSER_MODE 
CC=gcc
CCP=g++
POLICYOBJ= policy_ui.o 
POLICYHEADER= policy_ui.h
MEMDBOBJ = logic_vtpm.o logic_vm_policy.o logic_compare.o
#MEMDBHEADER= vtpm_struct.h vtpm_desc.h

main: test_main test_main1 test_main2 test_vmstruct
test_main:  test_main.c ../lib/libmemdb.a ../lib/libmemdb.so 
	$(CC) $(FLAGS) test_main test_main.c -L../lib -lpolicy_ui -lmemdb -lmessage -llogicdb -lcrypto_func -lstruct 
test_main1:  test_main1.c logic_vtpm.o ../lib/libpolicy_ui.a ../lib/libmemdb.a ../lib/liblogicdb.a ../lib/libstruct.a
	$(CC) $(FLAGS) test_main1 test_main.c -L../lib -lpolicy_ui -lmemdb -lmessage -llogicdb -lcrypto_func -lstruct 
test_main2:  test_main2.c logic_vtpm.o ../lib/libpolicy_ui.a ../lib/libmemdb.a ../lib/liblogicdb.a ../lib/libstruct.a
	$(CC) $(FLAGS) test_main2 test_main.c -L../lib -lpolicy_ui -lmemdb -lmessage -llogicdb -lcrypto_func -lstruct 
test_vmstruct:  test_vmstruct.c ../lib/libstruct.a
	$(CC) $(FLAGS) test_vmstruct test_vmstruct.c -L../lib -lmemdb -lstruct -lcrypto_func
logic_vtpm.o: logic_vtpm.c 
	$(CC) $(CFLAGS) logic_vtpm.c
logic_vm_policy.o: logic_vm_policy.c 
	$(CC) $(CFLAGS) logic_vm_policy.c
logic_compare.o: logic_compare.c logic_compare.h 
	$(CC) $(CFLAGS) logic_compare.c
../lib/libmemdb.so: $(MEMDBOBJ) 	
	gcc -shared -o libmemdb.so $(MEMDBOBJ) 
	mv libmemdb.so ../lib
../lib/libmemdb.a: $(MEMDBOBJ) 	
	ar rs libmemdb.a $(MEMDBOBJ) 
	mv libmemdb.a ../lib
policy_ui.o: policy_ui.c policy_ui.h
	$(CC) $(CFLAGS) policy_ui.c
clean:
	rm -f test_main test_main? test_vmstruct *~ *.o *.a ../lib/libmemdb.a ../lib/libmemdb.so
