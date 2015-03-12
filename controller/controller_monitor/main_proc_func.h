#ifndef MAIN_PROC_FUNC _H
#define MAIN_PROC_FUNC_H


enum main_proc_state
{
	PROC_DBCONNECT=0x1000,
	PROC_MONITOR,
	PROC_FAIL,
};

static NAME2VALUE main_state_list[]=
{
	{"dbconnect",PROC_DBCONNECT},
	{"monitor",PROC_MONITOR},
	{"fail",PROC_FAIL},
	{NULL,0},
};

static char * main_state_name[]=
{
	"dbconnect",
	"monitor",
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


int controller_monitor_init(void * proc,void * para);

int platform_info_memdb_init();
int image_info_memdb_init();
int vm_info_memdb_init();
int image_policy_memdb_init();
int vm_policy_memdb_init();
int platform_policy_memdb_init();

static char * monitor_process_state_name[]=
{
	"monitor_init",
	"monitor_scan",
	"monitor_sleep",
	"monitor_fail",
	NULL
};

int monitor_process_init(void * sub_proc,void * para);
int monitor_process_start(void * sub_proc,void * para);

static char * monitor_process_func_name[]=
{
	"vm",
	"platform",
	"image",
	NULL
};
#endif
