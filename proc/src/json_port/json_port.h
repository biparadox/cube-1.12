#ifndef JSON_PORT_FUNC_H
#define JSON_PORT_FUNC_H

struct init_struct
{
	char json_server_addr[DIGEST_SIZE];
	int  json_server_port;
};

static struct struct_elem_attr init_struct_desc[] =
{
        {"json_server_addr",OS210_TYPE_STRING,DIGEST_SIZE,NULL},
        {"json_server_port",OS210_TYPE_INT,0,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
// plugin's init func and kickstart func
int json_port_init(void * sub_proc,void * para);
int json_port_start(void * sub_proc,void * para);
struct timeval time_val={0,50*1000};

#endif
