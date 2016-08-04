FLAGS= -g -o 
LIBFLAGS = -g -shared -o
INCLUDE= -I$(CUBELIBPATH)/include/ -I$(CUBE_APP_INCLUDE)
CFLAGS= -g -c -fPIC -DUSER_MODE $(INCLUDE)
CC=gcc
CCP=g++
MAIN_PROC=TrustCA
INIT_OBJ=
TEST_LIB= -L$(CUBELIBPATH)/lib -lopenstacktrust -lentity -lrouter -lpolicy_ui -lmemdb -lconnector -ltesi -ltspi -lmessage -llogicdb -lstruct -lsysfunc -lcrypto_func -lpthread 

main: $(MAIN_PROC)
$(MAIN_PROC):  main_proc.c lib$(MAIN_PROC).so $(INIT_OBJ)
	$(CC) $(FLAGS) $(MAIN_PROC) main_proc.c $(INIT_OBJ) $(INCLUDE) $(TEST_LIB) -ldl
lib$(MAIN_PROC).so: $(MAIN_PROC)_func.o $(INIT_OBJ)
	$(CC) $(LIBFLAGS) lib$(MAIN_PROC).so $(INIT_OBJ) $(MAIN_PROC)_func.o $(TEST_LIB)
$(MAIN_PROC)_func.o: $(MAIN_PROC)_func.c main_proc_func.h
	$(CC) $(CFLAGS) $(MAIN_PROC)_func.c
clean:
	rm -f $(MAIN_PROC) *~ *.o *.a
	ln -s ../../proc/src/main/main_proc.c .
	ln -s ../../proc/src/main/main_proc_func.h
	export LD_LIBRARY_PATH=../lib
	sudo ldconfig
