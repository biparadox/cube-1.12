FLAGS= -g -o 
CFLAGS= -g -c -DUSER_MODE  -I../include
CC=gcc
CCP=g++
MAIN_PROC=interface_server
MAINPROC_OBJ=interface_server.o
MAINPROC_SRC=interface_server.c
SUBPROC_OBJ= json_port_func.o

main: $(MAIN_PROC)
$(MAIN_PROC):  main_proc.c connector_process_func.o router_process_func.o $(MAIN_PROC).o $(SUBPROC_OBJ) 
	$(CC) $(FLAGS) $(MAIN_PROC) main_proc.c connector_process_func.o router_process_func.o $(MAIN_PROC).o $(SUBPROC_OBJ) -L../lib -lopenstacktrust -lentity -lrouter -lpolicy_ui -lmemdb -lconnector -lmessage -llogicdb -lstruct -lsysfunc -lcrypto_func -lpthread
$(MAIN_PROC).o: $(MAIN_PROC_SRC) main_proc_func.h
	$(CC) $(CFLAGS) $(MAIN_PROC).c
readconfig.o: readconfig.c readconfig.h
	$(CC) $(CFLAGS) readconfig.c
json_port_func.o:  json_port_func.c json_port_func.h main_proc_func.h
	$(CC)  $(CFLAGS) json_port_func.c
clean:
	rm -f $(MAIN_PROC) *~ *.o *.a
	ln -s ../../general/connector_process_func.o .
	ln -s ../../general/router_process_func.o .
