FLAGS= -g -o 
LIBFLAGS = -g -shared -o
CFLAGS= -g -c -fPIC -DUSER_MODE 
CC=gcc
CCP=g++
MAIN_PROC=example_proc
PLUGIN_PROC_OBJ=libecho_plugin.so
INIT_OBJ=lib$(MAIN_PROC).so

main: $(MAIN_PROC)
$(MAIN_PROC):  main_proc.c $(MAIN_PROC)_func.o $(PLUGIN_PROC_OBJ) $(INIT_OBJ)
	$(CC) $(FLAGS) $(MAIN_PROC) main_proc.c -L../lib -lopenstacktrust -lentity -lrouter -lpolicy_ui -lmemdb -lconnector -lmessage -llogicdb -lstruct -lsysfunc -lcrypto_func -lpthread -ldl
$(INIT_OBJ): $(MAIN_PROC)_func.o
	$(CC) $(LIBFLAGS) $(INIT_OBJ) $(MAIN_PROC)_func.o
$(MAIN_PROC)_func.o: $(MAIN_PROC)_func.c main_proc_func.h
	$(CC) $(CFLAGS) $(MAIN_PROC)_func.c
libecho_plugin.so: echo_plugin_func.o
	$(CC) $(LIBFLAGS) libecho_plugin.so echo_plugin_func.o
echo_plugin_func.o:  echo_plugin_func.c main_proc_func.h
	$(CC)  $(CFLAGS) echo_plugin_func.c 
clean:
	rm -f $(MAIN_PROC) *~ *.o *.a
	ln -s ../../general/libconnector_process_func.so .
	ln -s ../../general/librouter_process_func.so .
	ln -s ../../general/main_proc.c .
