FLAGS= -g -shared -o
INCLUDE= -I$(CUBELIBPATH)/include/ 
CFLAGS= -g -c -fPIC -DUSER_MODE $(INCLUDE)
CC=gcc
CCP=g++
PLUGIN=file_dealer
PLUGIN_OBJ=
TEST_LIB= -L$(CUBELIBPATH)/lib -lopenstacktrust -lentity -lrouter -lpolicy_ui -lmemdb -lconnector -lmessage -llogicdb -lstruct -lsysfunc -lcrypto_func -lpthread

main: lib$(PLUGIN).so
lib$(PLUGIN).so:  $(PLUGIN).o $(PLUGIN_PROC_OBJ) $(INIT_DB_OBJ)
	$(CC) $(FLAGS) lib$(PLUGIN).so $(PLUGIN).o $(PLUGIN_OBJ) $(TEST_LIB)
	mv lib$(PLUGIN).so $(CUBE_SYS_PLUGIN)
$(PLUGIN).o: $(PLUGIN).c $(PLUGIN).h
	$(CC) $(CFLAGS) $(PLUGIN).c
clean:
	rm -f lib$(PLUGIN).so 
	rm  *.o *~
