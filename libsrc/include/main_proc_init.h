#ifndef MAIN_PROC_INIT_H
#define MAIN_PROC_INIT_H

typedef struct procdb_init_parameter
{
	char * name;
	int (*init)(char *,void *); 
	void * record_desc;
	void * recordlib_ops;
}PROCDB_INIT;

typedef struct connector_init_parameter
{
	char * name;
	int type;
	int family;
	char * addr;
	int attrflag;
	int proc_state; 
	int flagstate; 	
}CONN_INIT;

typedef struct proc_init_parameter
{
	char * name;
	int type;
	int (* init) (void *,void *);
	int (* start) (void *,void *);
}PROC_INIT;

   // this proc has these memory_database:
   // IMGI:  the image list of this cloud
   // VM_I:  all th vm created by the cloud
   // PLAI:  this cloud's platform information
extern int proc_conn_start(void * sub_proc, void * para);
extern int proc_conn_init(void * sub_proc,void * para);

static PROC_INIT conn_proc_initdata=
	{"connector_proc",PROC_TYPE_CONN, &proc_conn_init,&proc_conn_start};

extern int proc_router_start(void * sub_proc, void * para);
extern int proc_router_init(void * sub_proc,void * para);
static PROC_INIT router_proc_initdata=
	{"router_proc",PROC_TYPE_ROUTER, &proc_router_init,&proc_router_start};

struct conn_init_para
{
	void * hub;
	char * default_local_port;
	char * default_remote_port;
};

static struct struct_elem_attr share_data_desc[]=
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"proc_name",OS210_TYPE_ESTRING,DIGEST_SIZE*2,NULL},
	{"host_name",OS210_TYPE_ESTRING,DIGEST_SIZE*2,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static __inline__ int null_init_func(char * type, void * para) {return 0;};

#endif // PROC_CONFIG_H
