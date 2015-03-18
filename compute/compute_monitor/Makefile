FLAGS= -g -o 
CFLAGS= -g -c -DUSER_MODE  -I../include
CC=gcc
CCP=g++
MAIN_PROC=compute_monitor
MAINPROC_OBJ=compute_monitor_func.o
MAINPROC_SRC=compute_monitor_func.c
SUBPROC_OBJ=monitor_process_func.o	cloud_policy.o

main: $(MAIN_PROC)
$(MAIN_PROC):  main_proc.c connector_process_func.o router_process_func.o $(MAINPROC_OBJ) $(SUBPROC_OBJ) readconfig.o local_func.o
	$(CC) $(FLAGS) $(MAIN_PROC) main_proc.c connector_process_func.o router_process_func.o $(MAINPROC_OBJ) $(SUBPROC_OBJ) readconfig.o local_func.o -L../lib -lopenstacktrust -lentity -lrouter -lpolicy_ui -lmemdb -lconnector -lmessage -llogicdb -lstruct -lsysfunc -lcrypto_func -lpthread
$(MAINPROC_OBJ): $(MAINPROC_SRC) main_proc_func.h
	$(CC) $(CFLAGS) $(MAINPROC_SRC)
readconfig.o: readconfig.c readconfig.h
	$(CC) $(CFLAGS) readconfig.c
monitor_process_func.o:  monitor_process_func.c monitor_process_func.h main_proc_func.h
	$(CC)  $(CFLAGS) monitor_process_func.c 
cloud_policy.o:  cloud_policy.c cloud_policy.h 
	$(CC)  $(CFLAGS) cloud_policy.c 
local_func.o:  local_func.c local_func.h
	$(CC)  $(CFLAGS) local_func.c 
clean:
	rm -f $(MAIN_PROC) *~ *.o *.a
	ln -s ../../general/connector_process_func.o .
	ln -s ../../general/router_process_func.o .
