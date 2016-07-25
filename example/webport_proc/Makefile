FLAGS= -g -o 
LIBFLAGS = -g -shared -o
CFLAGS= -g -c -fPIC -DUSER_MODE 
CC=gcc
CCP=g++
MAIN_PROC=webport_proc
INIT_OBJ=general_lib_init.o

main: $(MAIN_PROC)
$(MAIN_PROC):  main_proc.c lib$(MAIN_PROC).so $(INIT_OBJ)
	$(CC) $(FLAGS) $(MAIN_PROC) main_proc.c $(INIT_OBJ) -L../lib -lopenstacktrust -lentity -lrouter -lpolicy_ui -lmemdb -lconnector -lmessage -llogicdb -lstruct -lsysfunc -lcrypto_func -lpthread -ldl
$lib$(MAIN_PROC).so: $(MAIN_PROC)_func.o
	$(CC) $(LIBFLAGS) $(INIT_OBJ) $(MAIN_PROC)_func.o
$(MAIN_PROC)_func.o: $(MAIN_PROC)_func.c main_proc_func.h
	$(CC) $(CFLAGS) $(MAIN_PROC)_func.c
general_lib_init.o:  general_lib_init.c general_lib_init.h
	$(CC)  $(CFLAGS) general_lib_init.c 
clean:
	rm -f $(MAIN_PROC) *~ *.o *.a
	ln -s ../../proc/src/main/main_proc.c .
	ln -s ../../proc/src/main/main_proc_func.h
	export LD_LIBRARY_PATH=../lib
	sudo ldconfig
