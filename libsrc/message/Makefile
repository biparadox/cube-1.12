FLAGS= -g -o 
CFLAGS= -g -c -DUSER_MODE 
CC=gcc
CCP=g++
MESSAGEOBJ = message.o load_message.o json_message.o
#MEMDBHEADER= vtpm_struct.h vtpm_desc.h

main: ../lib/libmessage.a test_main
test_main:  test_main.c ../lib/libmessage.a ../lib/liblogicdb.a ../lib/libstruct.a
	$(CC) $(FLAGS) test_main test_main.c -L../lib -lmessage -llogicdb -lstruct
../lib/libmessage.a: $(MESSAGEOBJ) 	
	ar rs libmessage.a $(MESSAGEOBJ)
	mv libmessage.a ../lib
message.o:  message.c message_box.h
	$(CC) $(CFLAGS) message.c 
load_message.o:  load_message.c message_box.h
	$(CC) $(CFLAGS) load_message.c 
json_message.o:  json_message.c message_box.h
	$(CC) $(CFLAGS) json_message.c 
clean:
	rm -f test_main *~ *.o *.a
