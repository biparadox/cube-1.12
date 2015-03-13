FLAGS= -g -o 
CFLAGS= -g -c -DUSER_MODE 
CC=gcc
CCP=g++
MAIN_PROC=manager_policy_func
MAINPROC_OBJ=manager_policy_func.o
MAINPROC_SRC=manager_policy_func.c
SUBPROC_OBJ=manager_vm_func.o  manager_image_func.o	manager_platform_func.o

main: manager_policy
manager_policy:  main_proc.c connector_process_func.o $(MAIN_PROC).o $(SUBPROC_OBJ) 
	$(CC) $(FLAGS) manager_policy main_proc.c connector_process_func.o router_process_func.o $(MAIN_PROC).o $(SUBPROC_OBJ) -L../lib -lopenstacktrust -lentity -lrouter -lpolicy_ui -lmemdb -lconnector -lmessage -llogicdb -lstruct -lsysfunc -lcrypto_func -lcrypto -lpthread
$(MAIN_PROC).o: $(MAIN_PROC).c main_proc_func.h
	$(CC) $(CFLAGS) $(MAIN_PROC).c
manager_vm_func.o:  manager_vm_func.c manager_vm_func.h main_proc_func.h
	$(CC)  $(CFLAGS) manager_vm_func.c 
manager_image_func.o:  manager_image_func.c manager_image_func.h main_proc_func.h
	$(CC)  $(CFLAGS) manager_image_func.c 
manager_platform_func.o:  manager_platform_func.c manager_platform_func.h main_proc_func.h
	$(CC)  $(CFLAGS) manager_platform_func.c 
local_func.o:  local_func.c local_func.h
	$(CC)  $(CFLAGS) local_func.c 
clean:
	rm -f manager_policy *~ *.o *.a
	ln -s ../../general/connector_process_func.o .
	ln -s ../../general/router_process_func.o .
