#ifndef MAIN_PROC_FUNC_H
#define MAIN_PROC_FUNC_H


static struct struct_elem_attr share_data_desc[]=
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"proc_name",OS210_TYPE_ESTRING,DIGEST_SIZE*2,NULL},
	{"aik_state",OS210_TYPE_ENUM,sizeof(int),NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

int trust_manager_init(void * proc,void * para);

int public_key_memdb_init();
int wrapped_key_memdb_init();
int vtpm_memdb_init();


// aik_casign plugin's init func and kickstart func
int aik_casign_init(void * sub_proc,void * para);
int aik_casign_start(void * sub_proc,void * para);

// ca_verify plugin's init func and kickstart func
int ca_verify_init(void * sub_proc,void * para);
int ca_verify_start(void * sub_proc,void * para);


#endif
