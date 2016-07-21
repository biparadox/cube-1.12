FLAGS= -g -o 
LIBFLAGS = -g -shared -o
CFLAGS= -g -c -fPIC -DUSER_MODE 
CC=gcc
CCP=g++
MAIN_PROC=webport_proc
INIT_OBJ=lib$(MAIN_PROC).so

main: $(MAIN_PROC)
$(MAIN_PROC):  main_proc.c $(MAIN_PROC)_func.o $(INIT_OBJ)
	$(CC) $(FLAGS) $(MAIN_PROC) main_proc.c -L../lib -lopenstacktrust -lentity -lrouter -lpolicy_ui -lmemdb -lconnector -lmessage -llogicdb -lstruct -lsysfunc -lcrypto_func -lpthread -ldl
$(INIT_OBJ): $(MAIN_PROC)_func.o
	$(CC) $(LIBFLAGS) $(INIT_OBJ) $(MAIN_PROC)_func.o
$(MAIN_PROC)_func.o: $(MAIN_PROC)_func.c main_proc_func.h
	$(CC) $(CFLAGS) $(MAIN_PROC)_func.c
clean:
	rm -f $(MAIN_PROC) *~ *.o *.a
	ln -s ../../proc/src/main/main_proc.c .
	ln -s ../../proc/src/main/main_proc_func.h
	export LD_LIBRARY_PATH=../lib
	sudo ldconfig
