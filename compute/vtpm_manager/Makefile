FLAGS= -g -o 
CFLAGS= -g -c -DUSER_MODE 
CC=gcc
CCP=g++

main: vtpm_manager
vtpm_manager:  vtpm_manager.c vtpm_manager_func.o ../lib/libmessage.a ../lib/liblogicdb.a ../lib/libstruct.a 
	$(CC) $(FLAGS) vtpm_manager vtpm_manager.c vtpm_manager_func.o -L../lib -L/usr/local/lib -lopenstacktrust -ltesi -ltspi -lcrypto -lpolicy_ui -lmemdb -lmessage -llogicdb -lsysfunc -lcrypto_func -lstruct -lconnector -lpthread
vtpm_manager_func.o: vtpm_manager_func.c vtpm_manager_func.h
	$(CC) $(CFLAGS) vtpm_manager_func.c
clean:
	rm -f vtpm_manager *~ *.o *.a *.lib *.key *.pem
