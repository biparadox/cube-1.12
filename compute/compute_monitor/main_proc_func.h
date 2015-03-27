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
	{"hostname",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"proc_name",OS210_TYPE_ESTRING,DIGEST_SIZE*2,NULL},
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
	"caready",
	"loadpubek",
	"fail",
	NULL
};

static char * main_func_name[]=
{
	"verifyaik",
	NULL
};


int compute_monitor_init(void * proc,void * para);

int image_policy_memdb_init();
int vm_policy_memdb_init();
int platform_policy_memdb_init();
int platform_info_memdb_init();
int pcr_policy_memdb_init();
int file_policy_memdb_init();


static char * monitor_process_state_name[]=
{
	"tpm_open",
	"loadcaprivkey",
	"waitingreq",
	"receivereq",
	"verifyreq",
	"signcert",
	"sendactiveblob",
	"fail",
	NULL
};

int monitor_process_init(void * sub_proc,void * para);
int monitor_process_start(void * sub_proc,void * para);

static char * monitor_process_func_name[]=
{
	"aik_casign",
	NULL
};


#endif
