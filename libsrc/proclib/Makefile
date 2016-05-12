FLAGS= -g -o 
CFLAGS= -g -c -DUSER_MODE 
CC=gcc
CCP=g++
TRUSTLIBOBJ = openstack_trust_lib.o 

main:../lib/libopenstacktrust.a
../lib/libopenstacktrust.a: $(TRUSTLIBOBJ) 	
	ar rs libopenstacktrust.a $(TRUSTLIBOBJ)
	mv libopenstacktrust.a ../lib
openstack_trust_lib.o:  openstack_trust_lib.c ../include/openstack_trust_lib.h 
	$(CC) $(CFLAGS) openstack_trust_lib.c 
clean:
	rm -f *~ *.o *.a *.lib ../lib/libopenstacktrustlib.a
