#ifndef JSON_PORT_FUNC_H
#define JSON_PORT_FUNC_H

static char local_jsonserver_addr[] = "0.0.0.0:12888";

// plugin's init func and kickstart func
int json_port_init(void * sub_proc,void * para);
int json_port_start(void * sub_proc,void * para);

#endif
