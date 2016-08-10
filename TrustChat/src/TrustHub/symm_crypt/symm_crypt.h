#ifndef SYMM_CRYPT_FUNC_H
#define SYMM_CRYPT_FUNC_H

struct init_struct
{
	char passwd[DIGEST_SIZE];
};

static struct struct_elem_attr init_struct_desc[] = {
        {"passwd",OS210_TYPE_STRING,DIGEST_SIZE,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

// plugin's init func and kickstart func
int symm_crypt_init(void * sub_proc,void * para);
int symm_crypt_start(void * sub_proc,void * para);
struct timeval time_val={0,50*1000};

#endif
