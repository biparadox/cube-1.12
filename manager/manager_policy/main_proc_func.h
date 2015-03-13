#ifndef MAIN_PROC_FUNC_H
#define MAIN_PROC_FUNC_H


enum main_proc_state
{
	PROC_READY=0x1000,
	PROC_START,
	PROC_FAIL,
};
static NAME2VALUE main_state_list[]=
{
	{"ready",PROC_READY},
	{"start",PROC_START},
	{"fail",PROC_FAIL},
	{NULL,0},
};
static char * main_state_name[]=
{
	"ready",
	"start",
	"fail",
	NULL
};

static struct struct_elem_attr share_data_desc[]=
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"proc_name",OS210_TYPE_ESTRING,DIGEST_SIZE*2,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static char * main_func_name[]=
{
	"verifyaik",
	NULL
};


int manager_policy_init(void * proc,void * para);

int vm_info_memdb_init(void * sub_proc,void * para);
int image_info_memdb_init(void * sub_proc,void * para);
int platform_info_memdb_init(void * sub_proc,void * para);
int vm_policy_memdb_init(void * sub_proc,void * para);
int image_policy_memdb_init(void * sub_proc,void * para);
int platform_policy_memdb_init(void * sub_proc,void * para);

static char * manager_vm_state_name[]=
{
	"tpm_open",
	"createkey",
	"sendreq",
	"receivesign",
	"activate",
	"verifycert",
	"fail",
	NULL
};

int manager_vm_init(void * sub_proc,void * para);
int manager_vm_start(void * sub_proc,void * para);

static char * manager_vm_func_name[]=
{
	"aik_request",
	"aik_activate",
	NULL
};

static char * manager_image_state_name[]=
{
	"tpm_open",
	"createkey",
	"sendreq",
	"receivesign",
	"activate",
	"verifycert",
	"fail",
	NULL
};

int manager_image_init(void * sub_proc,void * para);
int manager_image_start(void * sub_proc,void * para);

static char * manager_image_func_name[]=
{
	"aik_request",
	"aik_activate",
	NULL
};

static char * manager_platform_state_name[]=
{
	"tpm_open",
	"createkey",
	"sendreq",
	"receivesign",
	"activate",
	"verifycert",
	"fail",
	NULL
};

int manager_platform_init(void * sub_proc,void * para);
int manager_platform_start(void * sub_proc,void * para);

static char * manager_platform_func_name[]=
{
	"aik_request",
	"aik_activate",
	NULL
};

#endif
