#ifndef SERVER_MESSAGE_EXPAND_H
#define SERVER_MESSAGE_EXPAND_H
struct expand_time_stamp
{
	int data_size;
	char tag[4];
	char time[DIGEST_SIZE];
}__attribute__((packed));

static struct struct_elem_attr expand_time_stamp_desc[]=
{
	{"data_size",OS210_TYPE_INT,sizeof(int),NULL},
	{"tag",OS210_TYPE_STRING,4,NULL},
	{"time",OS210_TYPE_STRING,DIGEST_SIZE,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

// plugin's init func and kickstart func
int server_message_expand_init(void * sub_proc,void * para);
int server_message_expand_start(void * sub_proc,void * para);
struct timeval time_val={0,50*1000};

#endif
