FLAGS= -g -shared -o
CFLAGS= -g -c -fPIC -DUSER_MODE 
CC=gcc
CCP=g++
PLUGIN=echo_plugin
PLUGIN_OBJ=
TEST_LIB= -L../lib -lopenstacktrust -lentity -lrouter -lpolicy_ui -lmemdb -lconnector -lmessage -llogicdb -lstruct -lsysfunc -lcrypto_func -lpthread

main: test_main lib$(PLUGIN).so
test_main: test_main.c lib$(PLUGIN).so
	$(CC) -g -o test_main test_main.c -ldl 
lib$(PLUGIN).so:  $(PLUGIN).o $(PLUGIN_PROC_OBJ) $(INIT_DB_OBJ)
	$(CC) $(FLAGS) lib$(PLUGIN).so $(PLUGIN).o $(PLUGIN_OBJ) $(TEST_LIB)
$(PLUGIN).o: $(PLUGIN).c $(PLUGIN).h
	$(CC) $(CFLAGS) $(PLUGIN).c
clean:
	rm -f test_main lib$(PLUGIN).so 
	rm  *.o *~
