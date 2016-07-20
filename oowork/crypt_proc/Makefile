FLAGS= -g -o 
CFLAGS= -g -c -DUSER_MODE 
CC=gcc
CCP=g++
MAIN_PROC=crypt_proc
PLUGIN_PROC_OBJ=echo_plugin_func.o json_port_func.o  trust_bind_func.o trust_unbind_func.o
INIT_DB_OBJ=

main: $(MAIN_PROC)
$(MAIN_PROC):  main_proc.c $(MAIN_PROC)_func.o $(PLUGIN_PROC_OBJ) $(INIT_DB_OBJ)
	$(CC) $(FLAGS) $(MAIN_PROC) main_proc.c connector_process_func.o router_process_func.o $(MAIN_PROC)_func.o $(PLUGIN_PROC_OBJ) $(INIT_DB_OBJ)  -L../lib -lopenstacktrust -lentity -lrouter -ltesi -ltspi -lpolicy_ui -lmemdb -lconnector -lmessage -llogicdb -lstruct -lsysfunc -lcrypto_func -lcrypto -lpthread
$(MAIN_PROC)_func.o: $(MAIN_PROC)_func.c main_proc_func.h
	$(CC) $(CFLAGS) $(MAIN_PROC)_func.c
echo_plugin_func.o:  echo_plugin_func.c main_proc_func.h
	$(CC)  $(CFLAGS) echo_plugin_func.c 
json_port_func.o:  json_port_func.c main_proc_func.h
	$(CC)  $(CFLAGS) json_port_func.c 
trust_bind_func.o:  trust_bind_func.c trust_bind_func.h
	$(CC)  $(CFLAGS) trust_bind_func.c 
trust_unbind_func.o:  trust_unbind_func.c trust_unbind_func.h
	$(CC)  $(CFLAGS) trust_unbind_func.c 
clean:
	rm -f $(MAIN_PROC) *~ *.o *.a
	ln -s ../../general/connector_process_func.o .
	ln -s ../../general/router_process_func.o .
	ln -s ../../general/main_proc.c .
