#ifndef MAIN_PROC_FUNC_H
#define MAIN_PROC_FUNC_H
#include "../include/vtpm_struct.h"
#include "../include/vtpm_desc.h"
#include "echo_plugin_func.h"
#include "json_port_func.h"
#include "message_record.h"
#include "trust_bind_func.h"
#include "trust_unbind_func.h"


int crypt_proc_init();
int privkey_memdb_init(char * type, void * para);
int pubkey_memdb_init(char * type, void * para);


#endif
