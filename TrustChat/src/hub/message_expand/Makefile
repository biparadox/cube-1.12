FLAGS= -g -shared -o
CFLAGS= -g -c -fPIC -DUSER_MODE -I/home/algorist/backup/cube-1.12/cubelib/include/ -I../../include/
CC=gcc
CCP=g++
PLUGIN=message_expand
PLUGIN_OBJ=
TEST_LIB= -L../../../../lib -lopenstacktrust -lentity -lrouter -lpolicy_ui -lmemdb -lconnector -lmessage -llogicdb -lstruct -lsysfunc -lcrypto_func -lpthread 

main: lib$(PLUGIN).so
lib$(PLUGIN).so:  $(PLUGIN).o $(PLUGIN_PROC_OBJ) $(INIT_DB_OBJ)
	$(CC) $(FLAGS) lib$(PLUGIN).so $(PLUGIN).o $(PLUGIN_OBJ) $(TEST_LIB)
	mv lib$(PLUGIN).so ../plugin
	cp $(PLUGIN).cfg ../plugin
$(PLUGIN).o: $(PLUGIN).c $(PLUGIN).h
	$(CC) $(CFLAGS) $(PLUGIN).c
clean:
	rm -f test_main lib$(PLUGIN).so 
	rm  *.o *~
