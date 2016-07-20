#ifndef WEBSOCKET_PORT_FUNC_H
#define WEBSOCKET_PORT_FUNC_H

static char websocketserver_addr[] = "0.0.0.0";
static int websocket_port=13888;

// plugin's init func and kickstart func
int websocket_port_init(void * sub_proc,void * para);
int websocket_port_start(void * sub_proc,void * para);

#endif
