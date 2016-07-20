#ifndef NAMEVALUE
#define NAMEVALUE

typedef struct tagnameofvalue
{
	char * name;
	int value;
}NAME2VALUE;
static NAME2VALUE Audit_Probe_name[AUDIT_PROBE_END] = 
{
	{"SYS_START",AUDIT_PROBE_SYS_START},
	{"TASK_INITMARK",AUDIT_PROBE_TASK_INITMARK},
	{"INODE_INITMARK",AUDIT_PROBE_INODE_INITMARK},
	{"FILE_INITMARK",AUDIT_PROBE_FILE_INITMARK},
	{"CREATE_INODE",AUDIT_PROBE_CREATE_INODE},
	{"OPEN_FILE",AUDIT_PROBE_OPEN_FILE},
	{"READ_FILE",AUDIT_PROBE_READ_FILE},
	{"WRITE_FILE",AUDIT_PROBE_WRITE_FILE},
	{"EXEC_FILE",AUDIT_PROBE_EXEC_FILE},
	{"DELETE_FILE",AUDIT_PROBE_DELETE_FILE},
	{"DELETE_DIR",AUDIT_PROBE_DELETE_DIR},
	{"CREATE_DIR",AUDIT_PROBE_CREATE_DIR},
	{"SET_INODE_ATTR",AUDIT_PROBE_SET_INODE_ATTR},
	{"GET_INODE_ATTR",AUDIT_PROBE_GET_INODE_ATTR},
	{"MKNOD",AUDIT_PROBE_MKNOD},
	{"RENAME",AUDIT_PROBE_RENAME},
	{"NETWORK_ACCESS",AUDIT_PROBE_NETWORK_ACCESS},
	{"READ_INODE",AUDIT_PROBE_READ_INODE},
	{"WRITE_INODE",AUDIT_PROBE_WRITE_INODE},
	{"FORK",AUDIT_PROBE_FORK},
	{"EXIT",AUDIT_PROBE_EXIT},
	{"EXITGROUP",AUDIT_PROBE_EXITGROUP},
	{"LOGIN",AUDIT_PROBE_LOGIN},
	{"LOGOUT",AUDIT_PROBE_LOGOUT},
	{"MSG_QUEUE_ASSOCIATE",AUDIT_PROBE_MSG_QUEUE_ASSOCIATE},
	{"MSG_QUEUE_MSGCTL",AUDIT_PROBE_MSG_QUEUE_MSGCTL},
	{"MSG_QUEUE_MSGSND",AUDIT_PROBE_MSG_QUEUE_MSGSND},
	{"MSG_QUEUE_MSGRCV",AUDIT_PROBE_MSG_QUEUE_MSGRCV},	
	{"SHM_ASSOCIATE",AUDIT_PROBE_SHM_ASSOCIATE},
	{"SHM_SHMCTL",AUDIT_PROBE_SHM_SHMCTL},
	{"SHM_SHMAT",AUDIT_PROBE_SHM_SHMAT},
	{"SEM_ASSOCIATE",AUDIT_PROBE_SEM_ASSOCIATE},
	{"SEM_SEMCTL",AUDIT_PROBE_SEM_SEMCTL},
	{"SEM_SEMOP",AUDIT_PROBE_SEM_SEMOP},
	{"SOCKET_CREATE",AUDIT_PROBE_SOCKET_CREATE},
	{"SOCKET_BIND",AUDIT_PROBE_SOCKET_BIND},
	{"SOCKET_IOCTL",AUDIT_PROBE_SOCKET_IOCTL},
	{"SOCKET_CONNECT",AUDIT_PROBE_SOCKET_CONNECT},
	{"SOCKET_LISTEN",AUDIT_PROBE_SOCKET_LISTEN},
	{"SOCKET_ACCEPT",AUDIT_PROBE_SOCKET_ACCEPT},
	{"SOCKET_SENDMSG",AUDIT_PROBE_SOCKET_SENDMSG},
	{"SOCKET_RECVMSG",AUDIT_PROBE_SOCKET_RECVMSG},
	{"SOCKET_SETSOCKOPT",AUDIT_PROBE_SOCKET_SETSOCKOPT},
	{"SOCKET_GETSOCKOPT",AUDIT_PROBE_SOCKET_GETSOCKOPT},
	{"SETUID",AUDIT_PROBE_SETUID},
	{"GET_INODE",AUDIT_PROBE_GET_INODE},
	{"GET_FILE",AUDIT_PROBE_GET_FILE},
	{"REPEAT_READ",AUDIT_PROBE_REPEAT_READ},
	{"REPEAT_WRITE",AUDIT_PROBE_REPEAT_WRITE},
	{"",AUDIT_PROBE_END},
	{NULL,0}
};

static NAME2VALUE Audit_OpType_name[KAUDIT_TYPE_END] = 
{
	{"SUB_CREATE",KAUDIT_TYPE_SUB_CREATE},
	{"OBJ_CREATE",KAUDIT_TYPE_OBJ_CREATE},
	{"SUB_MARK",KAUDIT_TYPE_SUB_MARK},
	{"OBJ_MARK",KAUDIT_TYPE_OBJ_MARK},
	{"EXEC",KAUDIT_TYPE_EXEC},
	{"READ",KAUDIT_TYPE_READ},
	{"WRITE",KAUDIT_TYPE_WRITE},
	{"SUB_LOGIN",KAUDIT_TYPE_SUB_LOGIN},
	{"SUB_LOGOUT",KAUDIT_TYPE_SUB_LOGOUT},
	{"SUB_EXIT",KAUDIT_TYPE_SUB_EXIT},
	{"OBJ_DELETE",KAUDIT_TYPE_OBJ_DELETE},
	{"OBJ_RENAME",KAUDIT_TYPE_OBJ_RENAME},
//wdh 20110601
	{"SYS_START",KAUDIT_TYPE_SYS_START},
	{"IDENTIFY",KAUDIT_TYPE_IDENTIFY},
	{"SYS_HALT",KAUDIT_TYPE_SYS_HALT},
	{"POLICY_UPDATE",KAUDIT_TYPE_POLICY_UPDATE},
	{"EXPAND_SINGLE",KAUDIT_TYPE_EXPAND_SINGLE},
	{"EXPAND_HEAD",KAUDIT_TYPE_EXPAND_HEAD},
	{"EXPAND",KAUDIT_TYPE_EXPAND},
	{"EXPAND_TAIL",KAUDIT_TYPE_EXPAND_TAIL},
	{"END",KAUDIT_TYPE_END},
	{NULL,0}
};
static NAME2VALUE Audit_Retvalue_name[20] = 
{
	{"DAC Succ",VERIFY_DAC_SUCCESS},
	{"MAC Succ",VERIFY_MAC_SUCCESS},
	{"Priv Succ",VERIFY_PRIV_SUCCESS},
	{"Need Check",VERIFY_TRUST_NEEDCHECK},
	{"Failed",VERIFY_GENERAL_FAILED},
  	{NULL,0}
};
#endif