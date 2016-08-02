FLAGS= -g -shared -o
INCLUDE= $(CUBELIBPATH)/include/ 
CFLAGS= -g -c -fPIC -DUSER_MODE -I$(INCLUDE) -I$(CUBE_APP_INCLUDE)
CC=gcc
CCP=g++
PLUGIN=key_storage
PLUGIN_OBJ=
TEST_LIB= -L$(CUBELIBPATH)/lib -lopenstacktrust -lentity -lrouter -lpolicy_ui -lmemdb -lconnector -lmessage -llogicdb -lstruct -lsysfunc -lcrypto_func -lpthread 

main: lib$(PLUGIN).so
lib$(PLUGIN).so:  $(PLUGIN).o $(PLUGIN_PROC_OBJ) $(INIT_DB_OBJ)
	$(CC) $(FLAGS) lib$(PLUGIN).so $(PLUGIN).o $(PLUGIN_OBJ) $(TEST_LIB)
	mv lib$(PLUGIN).so $(CUBE_APP_PLUGIN)
	cp $(PLUGIN).cfg $(CUBE_APP_PLUGIN)
$(PLUGIN).o: $(PLUGIN).c $(PLUGIN).h
	$(CC) $(CFLAGS) $(PLUGIN).c
clean:
	rm -f test_main lib$(PLUGIN).so 
	rm  *.o *~
