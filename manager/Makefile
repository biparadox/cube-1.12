FLAGS= -g -o 
CFLAGS= -g -c -DUSER_MODE 
CC=gcc
CCP=g++
MAIN_PROC=verifier
MAINPROC_OBJ=verifier_func.o
MAINPROC_SRC=verifier_func.c
SUBPROC_OBJ=verifier_image_func.o	verifier_vm_func.o 	verifier_platform_func.o  cloud_policy.o  readconfig.o

main: policy_gen policy_image policy_compute policy_vm $(MAIN_PROC) 
$(MAIN_PROC):  main_proc.c connector_process_func.o router_process_func.o $(MAIN_PROC).o $(SUBPROC_OBJ) local_func.o
	$(CC) $(FLAGS) $(MAIN_PROC) main_proc.c connector_process_func.o router_process_func.o $(MAIN_PROC).o $(SUBPROC_OBJ) local_func.o -L../lib -lopenstacktrust -lentity -lrouter -ltesi -ltspi -lpolicy_ui -lmemdb -lconnector -lmessage -llogicdb -lstruct -lsysfunc -lcrypto_func -lpthread
$(MAIN_PROC).o: $(MAIN_PROC).c main_proc_func.h
	$(CC) $(CFLAGS) $(MAIN_PROC).c
policy_gen:	policy_gen.c readconfig.o  cloud_policy.o local_func.o ../lib/libmessage.a ../lib/liblogicdb.a ../lib/libstruct.a
	$(CC)  $(FLAGS)  policy_gen 	policy_gen.c	readconfig.o cloud_policy.o local_func.o -L../lib -lopenstacktrust -lentity -ltesi	-ltspi	-lcrypto -lpolicy_ui -lmemdb -lmessage -llogicdb  -lcrypto_func	-lstruct -lconnector -lsysfunc -lpthread
policy_image:	policy_image.c readconfig.o  cloud_policy.o local_func.o ../lib/libmessage.a ../lib/liblogicdb.a ../lib/libstruct.a
	$(CC)  $(FLAGS)  policy_image 	policy_image.c	readconfig.o cloud_policy.o local_func.o -L../lib -lopenstacktrust -lentity -ltesi	-ltspi	-lcrypto -lpolicy_ui -lmemdb -lmessage -llogicdb  -lcrypto_func	-lstruct -lconnector -lsysfunc -lpthread
policy_compute:	policy_compute.c readconfig.o  cloud_policy.o local_func.o ../lib/libmessage.a ../lib/liblogicdb.a ../lib/libstruct.a
	$(CC)  $(FLAGS)  policy_compute 	policy_compute.c	readconfig.o cloud_policy.o local_func.o -L../lib -lopenstacktrust -lentity -ltesi	-ltspi	-lcrypto -lpolicy_ui -lmemdb -lmessage -llogicdb  -lcrypto_func	-lstruct -lconnector -lsysfunc -lpthread
policy_vm:	policy_vm.c readconfig.o  cloud_policy.o local_func.o ../lib/libmessage.a ../lib/liblogicdb.a ../lib/libstruct.a
	$(CC)  $(FLAGS)  policy_vm 	policy_vm.c	readconfig.o cloud_policy.o local_func.o -L../lib -lopenstacktrust -lentity -ltesi	-ltspi	-lcrypto -lpolicy_ui -lmemdb -lmessage -llogicdb  -lcrypto_func	-lstruct -lconnector -lsysfunc -lpthread
readconfig.o: readconfig.c readconfig.h
	$(CC) $(CFLAGS) readconfig.c
verifier_image_func.o:  verifier_image_func.c verifier_image_func.h main_proc_func.h
	$(CC)  $(CFLAGS) verifier_image_func.c 
verifier_platform_func.o:  verifier_platform_func.c verifier_platform_func.h main_proc_func.h
	$(CC)  $(CFLAGS) verifier_platform_func.c 
verifier_vm_func.o:  verifier_vm_func.c verifier_vm_func.h main_proc_func.h
	$(CC)  $(CFLAGS) verifier_vm_func.c 
cloud_policy.o:  cloud_policy.c cloud_policy.h 
	$(CC)  $(CFLAGS) cloud_policy.c 
local_func.o:  local_func.c local_func.h
	$(CC)  $(CFLAGS) local_func.c 
clean:
	rm -f $(MAIN_PROC) policy_gen *~ *.o *.a
	ln -s ../../general/connector_process_func.o .
	ln -s ../../general/router_process_func.o .
