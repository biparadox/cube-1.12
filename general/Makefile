FLAGS= -g -o 
CFLAGS= -g -c -DUSER_MODE 
CC=gcc
CCP=g++

main: connector_process_func.o router_process_func.o libtest
connector_process_func.o: connector_process_func.c connector_process_func.h
	$(CC) $(CFLAGS) connector_process_func.c
router_process_func.o: router_process_func.c router_process_func.h
	$(CC) $(CFLAGS) router_process_func.c
libtest: libtest.c
	$(CC)  $(FLAGS) libtest libtest.c -L../lib -lopenstacktrust -lentity -lmessage -lpolicy_ui -lmemdb -llogicdb -lconnector -lcrypto_func -lstruct  -lpthread
#local_func.o:  local_func.c local_func.h
#	$(CC)  $(CFLAGS) local_func.c 
#main_proc.o:  main_proc.c 
#	$(CC)  $(CFLAGS) main_proc.c 
clean:
	rm -f *~ *.o *.a
