FLAGS= -g -o 
CFLAGS= -g -c -DUSER_MODE 
CC=gcc
CCP=g++
MAIN_PROC=test_verify
PLUGIN_PROC_OBJ=login_verify_func.o
INIT_DB_OBJ= general_lib_init.o

main: $(MAIN_PROC)
$(MAIN_PROC):  main_proc.c $(MAIN_PROC)_func.o $(PLUGIN_PROC_OBJ) $(INIT_DB_OBJ)
	$(CC) $(FLAGS) $(MAIN_PROC) main_proc.c connector_process_func.o router_process_func.o $(MAIN_PROC)_func.o $(PLUGIN_PROC_OBJ) $(INIT_DB_OBJ) -L../lib -lopenstacktrust -lentity -lrouter -lpolicy_ui -lmemdb -lconnector -lmessage -llogicdb -lstruct -lsysfunc -lcrypto_func -lpthread
$(MAIN_PROC)_func.o: $(MAIN_PROC)_func.c main_proc_func.h
	$(CC) $(CFLAGS) $(MAIN_PROC)_func.c
login_verify_func.o:  login_verify_func.c main_proc_func.h
	$(CC)  $(CFLAGS) login_verify_func.c 
general_lib_init.o:  general_lib_init.c general_lib_init.h
	$(CC)  $(CFLAGS) general_lib_init.c 
clean:
	rm -f example_proc *~ *.o *.a
	ln -s ../../general/connector_process_func.o .
	ln -s ../../general/router_process_func.o .
	ln -s ../../general/main_proc.c .
