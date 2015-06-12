FLAGS= -g -o 
CFLAGS= -g -c -DUSER_MODE 
CC=gcc
CCP=g++
MAIN_PROC=manager_policy
PLUGIN_PROC_OBJ=manager_vm_func.o manager_image_func.o manager_platform_func.o tree_info_func.o vm_find_host.o
INIT_DB_OBJ=

main: $(MAIN_PROC)
$(MAIN_PROC):  main_proc.c $(MAIN_PROC)_func.o $(PLUGIN_PROC_OBJ) $(INIT_DB_OBJ)
	$(CC) $(FLAGS) $(MAIN_PROC) main_proc.c connector_process_func.o router_process_func.o $(MAIN_PROC)_func.o $(PLUGIN_PROC_OBJ) $(INIT_DB_OBJ)  -L../lib -lopenstacktrust -lentity -lrouter -lpolicy_ui -lmemdb -lconnector -lmessage -llogicdb -lstruct -lsysfunc -lcrypto_func -lpthread
$(MAIN_PROC)_func.o: $(MAIN_PROC)_func.c main_proc_func.h
	$(CC) $(CFLAGS) $(MAIN_PROC)_func.c
manager_vm_func.o:  manager_vm_func.c manager_vm_func.h
	$(CC)  $(CFLAGS) manager_vm_func.c 
manager_image_func.o:  manager_image_func.c manager_image_func.h 
	$(CC)  $(CFLAGS) manager_image_func.c 
manager_platform_func.o:  manager_platform_func.c manager_platform_func.h 
	$(CC)  $(CFLAGS) manager_platform_func.c 
tree_info_func.o: tree_info_func.c tree_info_func.h
	$(CC)  $(CFLAGS) tree_info_func.c 
vm_find_host.o: vm_find_host.c vm_find_host.h
	$(CC)  $(CFLAGS) vm_find_host.c 
clean:
	rm -f $(MAIN_PROC) *~ *.o *.a
	ln -s ../../general/connector_process_func.o .
	ln -s ../../general/router_process_func.o .
	ln -s ../../general/main_proc.c .
