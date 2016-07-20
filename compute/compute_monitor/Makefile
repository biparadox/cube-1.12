FLAGS= -g -o 
CFLAGS= -g -c -DUSER_MODE  -I../include
CC=gcc
CCP=g++
MAIN_PROC=compute_monitor
MAINPROC_OBJ=compute_monitor_func.o
MAINPROC_SRC=compute_monitor_func.c
SUBPROC_OBJ=monitor_process_func.o	cloud_policy.o

main: $(MAIN_PROC) policy_compute policy_vm policy_image
$(MAIN_PROC):  main_proc.c connector_process_func.o router_process_func.o $(MAINPROC_OBJ) $(SUBPROC_OBJ) readconfig.o 
	$(CC) $(FLAGS) $(MAIN_PROC) main_proc.c connector_process_func.o router_process_func.o $(MAINPROC_OBJ) $(SUBPROC_OBJ) readconfig.o -L../lib -lopenstacktrust -lentity -lrouter -lpolicy_ui -lmemdb -lconnector -lmessage -llogicdb -lstruct -lsysfunc -lcrypto_func -lpthread
$(MAINPROC_OBJ): $(MAINPROC_SRC) main_proc_func.h
	$(CC) $(CFLAGS) $(MAINPROC_SRC)
policy_compute:	policy_compute.c readconfig.o  general_lib_init.o cloud_policy.o ../lib/libmessage.a ../lib/liblogicdb.a ../lib/libstruct.a
	$(CC)  $(FLAGS)  policy_compute 	policy_compute.c	general_lib_init.o readconfig.o cloud_policy.o -L../lib -lopenstacktrust -lentity -ltesi	-ltspi	-lcrypto -lpolicy_ui -lmemdb -lmessage -llogicdb  -lcrypto_func	-lconnector -lstruct -lsysfunc -lpthread
policy_vm:	policy_vm.c readconfig.o  cloud_policy.o local_func.o ../lib/libmessage.a ../lib/liblogicdb.a ../lib/libstruct.a
	$(CC)  $(FLAGS)  policy_vm 	policy_vm.c	readconfig.o cloud_policy.o local_func.o -L../lib -lopenstacktrust -lentity -ltesi	-ltspi	-lcrypto -lpolicy_ui -lmemdb -lmessage -llogicdb  -lcrypto_func	-lstruct -lconnector -lsysfunc -lpthread
policy_image:	policy_image.c readconfig.o  cloud_policy.o local_func.o ../lib/libmessage.a ../lib/liblogicdb.a ../lib/libstruct.a
	$(CC)  $(FLAGS)  policy_image 	policy_image.c	readconfig.o cloud_policy.o local_func.o -L../lib -lopenstacktrust -lentity -ltesi	-ltspi	-lcrypto -lpolicy_ui -lmemdb -lmessage -llogicdb  -lcrypto_func	-lstruct -lconnector -lsysfunc -lpthread
readconfig.o: readconfig.c readconfig.h
	$(CC) $(CFLAGS) readconfig.c
monitor_process_func.o:  monitor_process_func.c monitor_process_func.h main_proc_func.h
	$(CC)  $(CFLAGS) monitor_process_func.c 
cloud_policy.o:  cloud_policy.c cloud_policy.h 
	$(CC)  $(CFLAGS) cloud_policy.c 
general_lib_init.o:  general_lib_init.c general_lib_init.h 
	$(CC)  $(CFLAGS) general_lib_init.c 
clean:
	rm -f $(MAIN_PROC) *~ *.o *.a
	ln -s ../../general/connector_process_func.o .
	ln -s ../../general/router_process_func.o .
