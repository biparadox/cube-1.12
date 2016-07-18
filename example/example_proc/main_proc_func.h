#ifndef MAIN_PROC_FUNC_H
#define MAIN_PROC_FUNC_H

struct main_config
{
	char proc_name[DIGEST_SIZE];
	char * init_dlib;
	char * init_func;
	char * init_para;	
}__attribute__((packed));

static struct struct_elem_attr main_config_desc[]=
{
        {"proc_name",OS210_TYPE_STRING,DIGEST_SIZE,NULL},
        {"init_dlib",OS210_TYPE_ESTRING,DIGEST_SIZE*4,NULL},
        {"init_func",OS210_TYPE_ESTRING,DIGEST_SIZE*2,NULL},
        {"init_para",OS210_TYPE_ESTRING,DIGEST_SIZE*2,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

//#include "echo_plugin_func.h"


//int example_proc_init();


#endif
