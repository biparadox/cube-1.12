
#ifndef AIK_PROCESS_FUNC_H
#define AIK_PROCESS_FUNC_H
enum proc_caverify_state
{
	PROC_CA_LOADPRIVKEY=0x1000,
	PROC_CA_WAITINGREQ,
	PROC_CA_RECEIVEREQ,
	PROC_CA_VERIFYREQ,
	PROC_CA_SIGNCERT,
	PROC_CA_SENDRESULT,
	PROC_CA_FAIL,
};

static NAME2VALUE ca_state_list[]=
{
	{"loadprivkey",PROC_CA_LOADPRIVKEY},
	{"waitingreq",PROC_CA_WAITINGREQ},
	{"receivereq",PROC_CA_RECEIVEREQ},
	{"verifyreq",PROC_CA_VERIFYREQ},
	{"signcert",PROC_CA_SIGNCERT},
	{"sendresult",PROC_CA_SENDRESULT},
	{"fail",PROC_AIK_FAIL},
	{NULL,0}
};

int proc_ca_verify(void * sub_proc,void * message,void * pointer);

static NAME2POINTER aik_casign_func[]=
{
	{"ca_verify",&proc_ca_verify},
	{NULL,0}
};

#endif
