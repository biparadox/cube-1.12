FLAGS= -g -o 
CFLAGS= -g -c -DUSER_MODE 
CC=gcc
CCP=g++

main: client_manager
client_manager:  main_proc.c client_manager_func.o aik_process_func.o local_func.o
	$(CC) $(FLAGS) client_manager main_proc.c connector_process_func.o router_process_func.o client_manager_func.o aik_process_func.o local_func.o -L../lib -lopenstacktrust -lentity -lrouter -ltesi -ltspi -lpolicy_ui -lmemdb -lconnector -lmessage -llogicdb -lstruct -lsysfunc -lcrypto_func -lcrypto -lpthread
client_manager_func.o: client_manager_func.c main_proc_func.h
	$(CC) $(CFLAGS) client_manager_func.c
readconfig.o: readconfig.c readconfig.h
	$(CC) $(CFLAGS) readconfig.c
aik_process_func.o:  aik_process_func.c aik_process_func.h main_proc_func.h
	$(CC)  $(CFLAGS) aik_process_func.c 
local_func.o:  local_func.c local_func.h
	$(CC)  $(CFLAGS) local_func.c 
clean:
	rm -f client_manager *~ *.o *.a
	ln -s ../../general/connector_process_func.o .
	ln -s ../../general/router_process_func.o .
