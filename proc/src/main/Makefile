FLAGS= -g -shared -o 
INCLUDE= -I$(CUBELIBPATH)/include/ 
CFLAGS= -g -c -fPIC -DUSER_MODE $(INCLUDE)
CC=gcc
CCP=g++
TEST_LIB= -L$(CUBELIBPATH)/lib -lopenstacktrust -lentity -lrouter -lpolicy_ui -lmemdb -lconnector -lmessage -llogicdb -lstruct -lsysfunc -lcrypto_func -lpthread

main: libconnector_process_func.so librouter_process_func.so 
#main_proc:  main_proc.c main_proc_func.h
#	$(CC) $(FLAGS) main_proc main_proc.c $(TEST_LIB) -ldl
libconnector_process_func.so: connector_process_func.o connector_process_func.h
	$(CC) $(FLAGS) libconnector_process_func.so connector_process_func.o $(TEST_LIB)
	mv libconnector_process_func.so $(CUBE_SYS_PLUGIN)
librouter_process_func.so: router_process_func.o router_process_func.h
	$(CC) $(FLAGS) librouter_process_func.so router_process_func.o $(TEST_LIB)
	mv librouter_process_func.so $(CUBE_SYS_PLUGIN)
connector_process_func.o: connector_process_func.c connector_process_func.h
	$(CC) $(CFLAGS) connector_process_func.c 
router_process_func.o: router_process_func.c router_process_func.h
	$(CC) $(CFLAGS) router_process_func.c
libtest: libtest.c
	$(CC)  $(FLAGS) libtest libtest.c -L../lib -lopenstacktrust -lentity -lmessage -lpolicy_ui -lmemdb -llogicdb -lconnector -lcrypto_func -lstruct  -lpthread
clean:
	rm -f *~ *.o *.a *.so
