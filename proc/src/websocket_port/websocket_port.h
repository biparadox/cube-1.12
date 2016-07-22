#ifndef WEBSOCKET_PORT_FUNC_H
#define WEBSOCKET_PORT_FUNC_H

struct init_struct
{
	char ws_server_addr[DIGEST_SIZE];
	int  ws_server_port;
};
static struct struct_elem_attr init_struct_desc[] =
{
        {"ws_server_addr",OS210_TYPE_STRING,DIGEST_SIZE,NULL},
        {"ws_server_port",OS210_TYPE_INT,0,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

// plugin's init func and kickstart func
int websocket_port_init(void * sub_proc,void * para);
int websocket_port_start(void * sub_proc,void * para);
struct timeval time_val={0,50*1000};

#endif
