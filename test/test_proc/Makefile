FLAGS= -g -o 
CFLAGS= -g -c -DUSER_MODE 
CC=gcc
CCP=g++
MAIN_PROC=test_proc
PLUGIN_PROC_OBJ=echo_plugin_func.o websocket_func.o time_stamp_func.o

main: $(MAIN_PROC)
$(MAIN_PROC):  main_proc.c $(MAIN_PROC)_func.o $(PLUGIN_PROC_OBJ)
	$(CC) $(FLAGS) $(MAIN_PROC) main_proc.c connector_process_func.o router_process_func.o $(MAIN_PROC)_func.o $(PLUGIN_PROC_OBJ) -L../lib -lopenstacktrust -lentity -lrouter -lpolicy_ui -lmemdb -lconnector -lmessage -llogicdb -lstruct -lsysfunc -lcrypto_func -lpthread -lwebsockets
$(MAIN_PROC)_func.o: $(MAIN_PROC)_func.c main_proc_func.h
	$(CC) $(CFLAGS) $(MAIN_PROC)_func.c
echo_plugin_func.o:  echo_plugin_func.c main_proc_func.h
	$(CC)  $(CFLAGS) echo_plugin_func.c 
websocket_func.o:  websocket_func.c main_proc_func.h
	$(CC)  $(CFLAGS) websocket_func.c 
time_stamp_func.o:  time_stamp_func.c main_proc_func.h
	$(CC)  $(CFLAGS) time_stamp_func.c 
clean:
	rm -f example_proc *~ *.o *.a
	ln -s ../../general/connector_process_func.o .
	ln -s ../../general/router_process_func.o .
	ln -s ../../general/main_proc.c .
