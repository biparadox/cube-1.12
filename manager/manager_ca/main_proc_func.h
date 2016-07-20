#ifndef MAIN_PROC_FUNC_H
#define MAIN_PROC_FUNC_H

#include "login_verify_func.h"
#include "general_lib_init.h"
#include "../include/vtpm_desc.h"

int trust_manager_init();

int public_key_memdb_init();
int vtpm_memdb_init();



#endif
