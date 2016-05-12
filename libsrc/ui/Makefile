FLAGS= -g -o 
CFLAGS= -g -c -DUSER_MODE 
CC=gcc
CCP=g++
FUNCOBJ= policy_ui.o

main: ../lib/libpolicy_ui.a
#policy_test: policy_test.c ../lib/libpolicy_ui.a ../lib/liblogicdb.a ../lib/libstruct.a 
#	$(CC) $(FLAGS) policy_test policy_test.c libpolicy_ui.a -L../lib -llogicdb -lmemdb -lcrypto_func -lstruct
test_main:  test_main.c ../lib/libpolicy_ui.a ../lib/liblogicdb.a ../lib/libstruct.a
	$(CC) $(FLAGS) test_main test_main.c libpolicy_ui.a -L../lib -llogicdb -lmemdb -lcrypto_func -lstruct 
test_main1:  test_main1.c ../lib/libpolicy_ui.a ../lib/liblogicdb.a ../lib/libstruct.a
	$(CC) $(FLAGS) test_main1 test_main1.c libpolicy_ui.a -L../lib -llogicdb -lmemdb -lcrypto_func -lstruct
test_main2:  test_main2.c ../lib/libpolicy_ui.a ../lib/liblogicdb.a ../lib/libstruct.a
	$(CC) $(FLAGS) test_main2 test_main2.c libpolicy_ui.a -L../lib -llogicdb -lmemdb -lcrypto_func -lstruct
test_vmstruct:  test_vmstruct.c vmlist.h vmlist_desc.h ../lib/libstruct.a
	$(CC) $(FLAGS) test_vmstruct test_vmstruct.c -L../lib -lstruct
../lib/libpolicy_ui.a: $(FUNCOBJ) 	
	ar cr libpolicy_ui.a $(FUNCOBJ) 
	mv libpolicy_ui.a  ../lib/libpolicy_ui.a
#	ar cr policy_ui.a $(FUNCOBJ) $(STRUCTOBJ) $(LOGICOBJ)
#	$(CC) -shared -fPIC -o policy_ui.so $(FUNCOBJ) $(STRUCTOBJ) $(LOGICOBJ)
#	chcon -t textrel_shlib_t ui/policy_ui.so
#	cp ui/policy_ui.so tool/
policy_ui.o: policy_ui.c policy_ui.h
	$(CC) $(CFLAGS) policy_ui.c
#audit_ui.o: audit_ui.c policy_ui.h valuename.h
#	$(CC) $(CFLAGS) audit_ui.c
clean:
	rm -f test_main *~ *.o *.a
