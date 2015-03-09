#ifndef MAIN_PROC_FUNC_H
#define MAIN_PROC_FUNC_H


enum main_proc_state
{
	PROC_TPMOPEN=0x1000,
	PROC_CAREADY,
	PROC_LOADPUBEK,
	PROC_FAIL,
};

static struct struct_elem_attr share_data_desc[]=
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"proc_name",OS210_TYPE_ESTRING,DIGEST_SIZE*2,NULL},
	{"aik_state",OS210_TYPE_ENUM,sizeof(int),NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};


static NAME2VALUE main_state_list[]=
{
	{"tpm_open",PROC_TPMOPEN},
	{"caready",PROC_CAREADY},
	{"loadpubek",PROC_LOADPUBEK},
	{"fail",PROC_FAIL},
	{NULL,0},
};

static char * main_state_name[]=
{
	"tpm_open",
	"noaik",
	"aik_ready",
	"fail",
	NULL
};

static char * main_func_name[]=
{
	"verifyaik",
	NULL
};


int trust_manager_init(void * proc,void * para);

int public_key_memdb_init();
int wrapped_key_memdb_init();
int vtpm_memdb_init();

static char * proc_aikclient_state_name[]=
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

int proc_aikclient_init(void * sub_proc,void * para);
int proc_aikclient_start(void * sub_proc,void * para);

static char * proc_aikclient_func_name[]=
{
	"aik_request",
	"aik_activate",
	NULL
};

#endif
