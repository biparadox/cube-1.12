#ifndef SESSION_MSG_H
#define SESSION_MSG_H

enum chat_message_type
{
	MSG_GENERAL=0x01,
	MSG_PRIVATE=0x02,
	MSG_ANNOUNCED=0x04,
};

struct session_msg{
char uuid[DIGEST_SIZE*2];
char sender[DIGEST_SIZE];
char receiver[DIGEST_SIZE];
long  time;
char * msg;
int  flag;
};

static NAME2VALUE message_type_valuelist[] =
{
	{"GENERAL",MSG_GENERAL},
	{"PRIVATE",MSG_PRIVATE},
	{"ANNOUNCED",MSG_ANNOUNCED},
	{NULL,0}
	
};

static struct struct_elem_attr session_msg_desc[]=
{
        {"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
        {"sender",OS210_TYPE_STRING,DIGEST_SIZE,NULL},
        {"receiver",OS210_TYPE_STRING,DIGEST_SIZE,NULL},
        {"time",OS210_TYPE_TIME,sizeof(long),NULL},
        {"msg",OS210_TYPE_ESTRING,512,NULL},
        {"flag",OS210_TYPE_FLAG,sizeof(int),&message_type_valuelist},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

enum  user_conn_state
{
	USER_CONN_CONNECTED=0x01,
	USER_CONN_SHUTDOWN=0x02,
	USER_CONN_ERROR=0xFF,

};

static NAME2VALUE user_conn_state_valuelist[] =
{
	{"CONNECTED",USER_CONN_CONNECTED},
	{"SHUTDOWN",USER_CONN_SHUTDOWN},
	{"ERROR",USER_CONN_ERROR},
	{NULL,0}
	
};


struct user_addr_list
{
	char user[DIGEST_SIZE];
	BYTE addr[DIGEST_SIZE*2];
	enum user_conn_state state;
	
};

static struct struct_elem_attr user_addr_list_desc[]=
{
        {"user",OS210_TYPE_STRING,DIGEST_SIZE,NULL},
        {"addr",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
        {"state",OS210_TYPE_ENUM,sizeof(int),&message_type_valuelist},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};


// plugin's init func and kickstart func

struct expand_flow_trace
{
	int data_size;
	char type[4];
	int record_num;
	char * trace_record;
}__attribute__((packed));

enum cloud_node_type
{
	CLOUD_CONTROLLER=0x01,
	CLOUD_HOST=0x02,
	CLOUD_VM=0x03,
	CLOUD_CA=0x04,
	CLOUD_NETCONTROLLER=0x05,
	CLOUD_BOUNDARY=0x06,
	CLOUD_ENDPOINT=0x07,
	CLOUD_PROVIDER_SYSMANAGER=0x10,
	CLOUD_PROVIDER_SECMANAGER=0x11,
	CLOUD_PROVIDER_AUDITOR=0x12,
	CLOUD_TENANT_SYSMANAGER=0x20,
	CLOUD_TENANT_SECMANAGER=0x21,
	CLOUD_TENANT_AUDITOR=0x22,
	CLOUD_APP=0x1000
};

struct node_key_list   // NKLD
{
	BYTE nodeuuid[DIGEST_SIZE*2];
	BYTE localuuid[DIGEST_SIZE*2];
	char nodename[DIGEST_SIZE];
	char username[DIGEST_SIZE];
	int  isnodelocal;   // bool value, 1 indicates that this node is local node, 0 indicates that this node is 
	enum cloud_node_type  nodetype;
	BYTE nodeAIK[DIGEST_SIZE*2];
	BYTE nodeAIKSda[DIGEST_SIZE*2];
	BYTE nodeBindKey[DIGEST_SIZE*2];
	BYTE nodeBindKeyVal[DIGEST_SIZE*2];
	BYTE nodeSignKey[DIGEST_SIZE*2];
	BYTE nodeSignKeyVal[DIGEST_SIZE*2];
}__attribute__((packed));

static NAME2VALUE cloud_node_type_valuelist[] =
{
	{"CONTROLLER",CLOUD_CONTROLLER},
	{"HOST",CLOUD_HOST},
	{"VM",CLOUD_VM},
	{"CA",CLOUD_CA},
	{"NETCONTROLLER",CLOUD_NETCONTROLLER},
	{"BOUNDARY",CLOUD_BOUNDARY},
	{"ENDPOINT",CLOUD_ENDPOINT},
	{"PROVIDER_SYSMANAGER",CLOUD_PROVIDER_SYSMANAGER},
	{"PROVIDER_SECMANAGER",CLOUD_PROVIDER_SECMANAGER},
	{"PROVIDER_AUDITOR",CLOUD_PROVIDER_AUDITOR},
	{"TENANT_SYSMANAGER",CLOUD_TENANT_SYSMANAGER},
	{"TENANT_SECMANAGER",CLOUD_TENANT_SECMANAGER},
	{"TENANT_AUDITOR",CLOUD_TENANT_AUDITOR},
	{"APP",CLOUD_APP},
	{NULL,0}
};

static struct struct_elem_attr node_key_list_desc[]=
{
        {"nodeuuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
        {"localuuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
        {"nodename",OS210_TYPE_STRING,DIGEST_SIZE,NULL},
        {"username",OS210_TYPE_STRING,DIGEST_SIZE,NULL},
        {"isnodelocal",OS210_TYPE_INT,sizeof(int),NULL},
        {"nodetype",OS210_TYPE_ENUM,sizeof(int),&cloud_node_type_valuelist},
        {"nodeAIK",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
        {"nodeAIKSda",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
        {"nodeBindKey",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
        {"nodeBindKeyVal",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
        {"nodeSignKey",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
        {"nodeSignKeyVal",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

// plugin's init func and kickstart func
#endif
