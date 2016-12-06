FLAGS= -g -shared -o
INCLUDE= -I$(CUBELIBPATH)/include/ 
CFLAGS= -g -c -fPIC -DUSER_MODE $(INCLUDE)
CC=gcc
CCP=g++
PLUGIN=bubble_sort
PLUGIN_OBJ= data_listen.o
TEST_LIB= -L$(CUBELIBPATH)/lib -lopenstacktrust -lentity -lrouter -lpolicy_ui -lmemdb -lconnector -lmessage -llogicdb -lstruct -lsysfunc -lcrypto_func -lpthread

main: lib$(PLUGIN).so
lib$(PLUGIN).so:  $(PLUGIN).o $(PLUGIN_OBJ)
	$(CC) $(FLAGS) lib$(PLUGIN).so $(PLUGIN).o $(PLUGIN_OBJ) $(TEST_LIB)
	mv lib$(PLUGIN).so $(CUBE_SYS_PLUGIN)
	cp $(PLUGIN).cfg $(CUBE_SYS_PLUGIN)
$(PLUGIN).o: $(PLUGIN).c $(PLUGIN).h
	$(CC) $(CFLAGS) $(PLUGIN).c
data_listen.o:data_listen.c
	$(CC) $(CFLAGS) data_listen.c
clean:
	rm -f test_main lib$(PLUGIN).so 
	rm  *.o *~
