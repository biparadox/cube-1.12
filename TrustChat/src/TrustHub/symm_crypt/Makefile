FLAGS= -g -shared -o
INCLUDE= $(CUBELIBPATH)/include/ 
CFLAGS= -g -c -fPIC -DUSER_MODE -I$(INCLUDE) -I$(CUBE_APP_INCLUDE)
CC=gcc
CCP=g++
PLUGIN=symm_crypt
PLUGIN_OBJ= sm4.o
TEST_LIB= -L$(CUBELIBPATH)/lib -lopenstacktrust -lentity -lrouter -lpolicy_ui -lmemdb -lconnector -lmessage -llogicdb -lstruct -lsysfunc -lcrypto_func -lpthread 

main: lib$(PLUGIN).so
lib$(PLUGIN).so:  $(PLUGIN).o $(PLUGIN_OBJ)
	$(CC) $(FLAGS) lib$(PLUGIN).so $(PLUGIN).o $(TEST_LIB)
	mv lib$(PLUGIN).so $(CUBE_APP_PLUGIN)
	cp $(PLUGIN).cfg $(CUBE_APP_PLUGIN)
$(PLUGIN).o: $(PLUGIN).c $(PLUGIN_OBJ) $(PLUGIN).h
	$(CC) $(CFLAGS) $(PLUGIN).c $(PLUGIN_OBJ)
sm4.o:	sm4.h sm4.c
	$(CC) $(CFLAGS) sm4.c
clean:
	rm -f test_main lib$(PLUGIN).so 
	rm  *.o *~
