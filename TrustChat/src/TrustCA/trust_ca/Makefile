FLAGS= -g -o 
INCLUDE= -I$(CUBELIBPATH)/include/ -I$(CUBE_APP_INCLUDE)
CFLAGS= -g -c -fPIC -DUSER_MODE  $(INCLUDE)
CC=gcc
CCP=g++
STRUCTOBJ= cube_cafunc.o
TEST_LIB= -L$(CUBELIBPATH)/lib -lopenstacktrust -lentity -lrouter -lpolicy_ui -lmemdb -lconnector -ltesi -ltspi -lcrypto -lmessage -llogicdb -lstruct -lsysfunc -lcrypto_func -lpthread 

main: test_main ca_create_crt
test_main: test_main.c cube_cafunc.o
	$(CC) $(FLAGS) test_main test_main.c $(STRUCTOBJ) $(INCLUDE) $(TEST_LIB)
ca_create_crt: ca_create_crt.c cube_cafunc.o
	$(CC) $(FLAGS) ca_create_crt ca_create_crt.c $(STRUCTOBJ) $(INCLUDE) $(TEST_LIB)
cube_cafunc.o  :  cube_cafunc.c cube_cafunc.h
	$(CC) $(CFLAGS) cube_cafunc.c 
clean:
	rm -f test_main *~ *.o *.a
