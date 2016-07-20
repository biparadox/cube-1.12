FLAGS= -g -o 
CFLAGS= -g -c -fPIC -DUSER_MODE 
CC=gcc
CCP=g++
TRUSTLIBOBJ = sec_object.o sec_subject.o sec_msgqueue.o sec_res.o

main:../lib/libentity.a ../lib/libentity.so
../lib/libentity.so: $(TRUSTLIBOBJ) 	
	$(CC) -shared -o libentity.so $(TRUSTLIBOBJ)
	mv libentity.so ../lib
../lib/libentity.a: $(TRUSTLIBOBJ) 	
	ar rs libentity.a $(TRUSTLIBOBJ)
	mv libentity.a ../lib
sec_object.o:  sec_object.c ../include/sec_entity.h
	$(CC) $(CFLAGS) sec_object.c 
sec_res.o:  sec_res.c ../include/sec_entity.h
	$(CC) $(CFLAGS) sec_res.c 
sec_subject.o:  sec_subject.c ../include/sec_entity.h
	$(CC) $(CFLAGS) sec_subject.c 
sec_msgqueue.o:  sec_msgqueue.c ../include/sec_entity.h
	$(CC) $(CFLAGS) sec_msgqueue.c 
clean:
	rm -f *~ *.o *.a *.lib ../lib/libentity.a ../lib/libentity.so
