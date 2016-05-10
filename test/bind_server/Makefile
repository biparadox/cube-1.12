FLAGS= -g -o 
CFLAGS= -g -c -DUSER_MODE 
CC=gcc
CCP=g++
MAIN_PROC=bind_server
PLUGIN_PROC_OBJ=  aik_process_func.o general_lib_init.o key_response_func.o server_unbind_func.o
INIT_DB_OBJ=

main: $(MAIN_PROC)
$(MAIN_PROC):  main_proc.c $(MAIN_PROC)_func.o $(PLUGIN_PROC_OBJ) $(INIT_DB_OBJ)
	$(CC) $(FLAGS) $(MAIN_PROC) main_proc.c connector_process_func.o router_process_func.o $(MAIN_PROC)_func.o $(PLUGIN_PROC_OBJ) $(INIT_DB_OBJ) -L../lib -lopenstacktrust -lentity -lrouter -ltesi -ltspi -lpolicy_ui -lmemdb -lconnector -lmessage -llogicdb -lstruct -lsysfunc -lcrypto_func -lcrypto -lpthread
$(MAIN_PROC)_func.o: $(MAIN_PROC)_func.c main_proc_func.h
	$(CC) $(CFLAGS) $(MAIN_PROC)_func.c
aik_process_func.o:  aik_process_func.c main_proc_func.h
	$(CC)  $(CFLAGS) aik_process_func.c 
general_lib_init.o:  general_lib_init.c general_lib_init.h
	$(CC)  $(CFLAGS) general_lib_init.c 
key_response_func.o:  key_response_func.c main_proc_func.h
	$(CC)  $(CFLAGS) key_response_func.c 
server_unbind_func.o:  server_unbind_func.c main_proc_func.h
	$(CC)  $(CFLAGS) server_unbind_func.c 
cleankey:
	rm -f cert/*.req cert/AIK.sda cert/bindkey.val lib/* privkey/* pubkey/AIK.pem pubkey/bindpubkey.pem
clean:
	rm -f $(MAIN_PROC) *~ *.o *.a
	ln -s ../../general/connector_process_func.o .
	ln -s ../../general/router_process_func.o .
	ln -s ../../general/main_proc.c .
