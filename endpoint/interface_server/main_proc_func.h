#ifndef MAIN_PROC_FUNC_H
#define MAIN_PROC_FUNC_H

enum interface_server_state
{
    PROC_READY=0x1000,
	PROC_FAIL,
};
static NAME2VALUE interface_server_list[]=
{
    {"ready",PROC_READY},
	{"fail",PROC_FAIL},
	{NULL,0},
};

static char * interface_server_state_name[]=
{
    "ready",
	"fail",
	NULL
};


static struct struct_elem_attr share_data_desc[]=
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"proc_name",OS210_TYPE_ESTRING,DIGEST_SIZE*2,NULL},
	{"verify_result",OS210_TYPE_INT,sizeof(int),NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};


static char * interface_server_func_name[]=
{
    "verifyaik",
	NULL
};

int interface_server_init(void * proc, void * para);

int vm_info_memdb_init();
int image_info_memdb_init();
int platform_info_memdb_init();
int vm_policy_memdb_init();
int pcr_policy_memdb_init();
int file_policy_memdb_init();

static char * json_port_state_name[]=
{
    "init",
    "open",
	NULL
};

int json_port_init(void * sub_proc,void * para);
int json_port_start(void * sub_proc,void * para);

static char * json_port_func_name[]=
{
    "json_port_json2struct",
    "json_port_struct2json",
	NULL
};

#endif
