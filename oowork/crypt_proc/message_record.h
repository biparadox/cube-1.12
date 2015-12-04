#ifndef MESSAGE_STRUCT_H
#define MESSAGE_STRUCT_H

struct message_record           // this record's type is MSGD 
{
	char * message;        //the message's content
}__attribute__((packed));

struct keyid_expand
{
	int data_size;         //the uuid of vm(or physical machine)
	char tag[4];		// should be KIDE
	char keyid[DIGEST_SIZE*2];	//this uuid can be used to identify the key used  
}__attribute__((packed));

static struct struct_elem_attr message_record_desc[]=
{
	{"message",OS210_TYPE_ESTRING,1024,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr expand_data_keyid_desc[]=
{
	{"data_size",OS210_TYPE_INT,sizeof(int),NULL},
	{"tag",OS210_TYPE_STRING,4,NULL},
	{"keyid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

#endif
