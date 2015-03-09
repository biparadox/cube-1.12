FLAGS= -g -o 
CFLAGS= -g -c -DUSER_MODE 
CC=gcc
CCP=g++

main: trust_manager
trust_manager:  main_proc.c trust_manager_func.o aik_casign_func.o ca_verify_func.o local_func.o
	$(CC) $(FLAGS) trust_manager main_proc.c connector_process_func.o router_process_func.o trust_manager_func.o aik_casign_func.o ca_verify_func.o local_func.o -L../lib -lopenstacktrust -lentity -lrouter -ltesi -ltspi -lpolicy_ui -lmemdb -lconnector -lmessage -llogicdb -lstruct -lsysfunc -lcrypto_func -lcrypto -lpthread
trust_manager_func.o: trust_manager_func.c main_proc_func.h
	$(CC) $(CFLAGS) trust_manager_func.c
readconfig.o: readconfig.c readconfig.h
	$(CC) $(CFLAGS) readconfig.c
aik_casign_func.o:  aik_casign_func.c aik_casign_func.h main_proc_func.h
	$(CC)  $(CFLAGS) aik_casign_func.c 
ca_verify_func.o:  ca_verify_func.c ca_verify_func.h main_proc_func.h
	$(CC)  $(CFLAGS) ca_verify_func.c 
local_func.o:  local_func.c local_func.h
	$(CC)  $(CFLAGS) local_func.c 
clean:
	rm -f trust_manager *~ *.o *.a
	ln -s ../../general/connector_process_func.o .
	ln -s ../../general/router_process_func.o .
