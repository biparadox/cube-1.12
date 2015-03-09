
#ifndef AIK_PROCESS_FUNC_H
#define AIK_PROCESS_FUNC_H
enum proc_aik_state
{
	PROC_AIK_TPMOPEN=0x1000,
	PROC_AIK_CREATEKEY,
	PROC_AIK_SENDREQ,
	PROC_AIK_RECEIVESIGN,
	PROC_AIK_ACTIVATE,
	PROC_AIK_VERIFYCERT,
	PROC_AIK_FAIL,
};

static NAME2VALUE aik_state_list[]=
{
	{"tpm_open",PROC_AIK_TPMOPEN},
	{"createkey",PROC_AIK_CREATEKEY},
	{"sendreq",PROC_AIK_SENDREQ},
	{"receivesign",PROC_AIK_RECEIVESIGN},
	{"activate",PROC_AIK_ACTIVATE},
	{"verifycert",PROC_AIK_VERIFYCERT},
	{"fail",PROC_AIK_FAIL},
	{NULL,0}
};

int proc_aik_request(void * sub_proc,void * message,void * pointer);
int proc_aik_activate(void * sub_proc,void * message,void * pointer);


static NAME2POINTER aik_process_func[]=
{
	{"aik_request",&proc_aik_request},
	{"aik_activate",&proc_aik_activate},
	{NULL,0}
};

#endif
