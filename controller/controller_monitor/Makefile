FLAGS= -g -o 
CFLAGS= -g -c -DUSER_MODE 
CC=gcc
CCP=g++
MAIN_PROC=controller_monitor
PLUGIN_PROC_OBJ=monitor_process_func.o cloud_policy.o local_func.o readconfig.o
INIT_DB_OBJ=

main: $(MAIN_PROC)
$(MAIN_PROC):  main_proc.c $(MAIN_PROC)_func.o $(PLUGIN_PROC_OBJ) $(INIT_DB_OBJ)
	$(CC) $(FLAGS) $(MAIN_PROC) main_proc.c connector_process_func.o router_process_func.o $(MAIN_PROC)_func.o $(PLUGIN_PROC_OBJ) $(INIT_DB_OBJ)  -L../lib -lopenstacktrust -lentity -lrouter -lmysqlclient -lpolicy_ui -lmemdb -lconnector -lmessage -llogicdb -lstruct -lsysfunc -lcrypto_func -lpthread
$(MAIN_PROC)_func.o: $(MAIN_PROC)_func.c main_proc_func.h
	$(CC) $(CFLAGS) $(MAIN_PROC)_func.c
monitor_process_func.o:  monitor_process_func.c monitor_process_func.h main_proc_func.h
	$(CC)  $(CFLAGS) monitor_process_func.c 
cloud_policy.o:  cloud_policy.c cloud_policy.h 
	$(CC)  $(CFLAGS) cloud_policy.c 
local_func.o:  local_func.c local_func.h
	$(CC)  $(CFLAGS) local_func.c 
readconfig.o: readconfig.c readconfig.h
	$(CC) $(CFLAGS) readconfig.c
clean:
	rm -f $(MAIN_PROC) *~ *.o *.a
	ln -s ../../general/connector_process_func.o .
	ln -s ../../general/router_process_func.o .
	ln -s ../../general/main_proc.c .
