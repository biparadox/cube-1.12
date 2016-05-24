#ifndef MESSAGE_STRUCT_DESC_H
#define MESSAGE_STRUCT_DESC_H
#include "../include/data_type.h"
#include "../include/struct_deal.h"
#define DIGEST_SIZE 32
//the decription struct of vm's policy
static struct struct_elem_attr message_head_desc[]=
{
	{"tag",OS210_TYPE_STRING,4,NULL},
	{"version",OS210_TYPE_INT,sizeof(UINT32),NULL},
	{"sender_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"receiver_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"flow",OS210_TYPE_FLAG,sizeof(UINT32),message_flow_valuelist},
	{"state",OS210_TYPE_ENUM,sizeof(UINT32),message_flow_valuelist},
	{"flag",OS210_TYPE_FLAG,sizeof(UINT32),message_flag_valuelist},
	{"record_type",OS210_TYPE_STRING,4,NULL},
	{"record_num",OS210_TYPE_INT,sizeof(UINT32),NULL},
	{"record_size",OS210_TYPE_INT,sizeof(UINT32),NULL},
	{"expand_num",OS210_TYPE_INT,sizeof(UINT32),NULL},
	{"expand_size",OS210_TYPE_INT,sizeof(UINT32),NULL},
	{"nonce",OS210_TYPE_BINDATA,DIGEST_SIZE,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr connect_syn_desc[]=
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"server_name",OS210_TYPE_ESTRING,256,NULL},
	{"service",OS210_TYPE_ESTRING,64,NULL},
	{"server_addr",OS210_TYPE_ESTRING,256,NULL},
	{"flags",OS210_TYPE_INT,sizeof(UINT32),NULL},
	{"nonce",OS210_TYPE_STRING,DIGEST_SIZE,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr connect_ack_desc[]=
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"client_name",OS210_TYPE_ESTRING,256,NULL},
	{"client_process",OS210_TYPE_ESTRING,64,NULL},
	{"client_addr",OS210_TYPE_ESTRING,256,NULL},
	{"server_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"server_name",OS210_TYPE_ESTRING,256,NULL},
	{"service",OS210_TYPE_ESTRING,64,NULL},
	{"server_addr",OS210_TYPE_ESTRING,256,NULL},
	{"flags",OS210_TYPE_INT,sizeof(UINT32),NULL},
	{"nonce",OS210_TYPE_STRING,DIGEST_SIZE,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr expand_data_identity_desc[]=
{
	{"data_size",OS210_TYPE_INT,sizeof(int),NULL},
	{"tag",OS210_TYPE_STRING,4,NULL},
	{"nonce",OS210_TYPE_BINDATA,DIGEST_SIZE,NULL},
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"user_name",OS210_TYPE_ESTRING,256,NULL},
	{"type",OS210_TYPE_INT,sizeof(int),NULL},
	{"pubkey_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"blob_size",OS210_TYPE_INT,sizeof(int),NULL},
	{"blob",OS210_TYPE_DEFINE,1,"blob_size"},
	{"digest",OS210_TYPE_BINDATA,DIGEST_SIZE,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr expand_data_forward_desc[]=
{
	{"data_size",OS210_TYPE_INT,sizeof(int),NULL},
	{"tag",OS210_TYPE_STRING,4,NULL},
	{"nonce",OS210_TYPE_BINDATA,DIGEST_SIZE,NULL},
	{"sender_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"sender_name",OS210_TYPE_ESTRING,256,NULL},
	{"receiver_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"receiver_name",OS210_TYPE_ESTRING,256,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr expand_extra_info_desc[]=
{
	{"data_size",OS210_TYPE_INT,sizeof(int),NULL},
	{"tag",OS210_TYPE_STRING,4,NULL},
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};


static struct struct_elem_attr connect_login_desc[]=
{
	{"user",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"passwd",OS210_TYPE_STRING,DIGEST_SIZE,NULL},
	{"nonce",OS210_TYPE_BINDATA,DIGEST_SIZE,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr connect_return_desc[]=
{
	{"retval",OS210_TYPE_INT,sizeof(int),NULL},
	{"ret_data_size",OS210_TYPE_INT,sizeof(int),NULL},
	{"ret_data",OS210_TYPE_DEFSTR,1,"ret_data_size"},
	{"nonce",OS210_TYPE_BINDATA,DIGEST_SIZE,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr request_cmd_desc[]=
{
	{"tag",OS210_TYPE_STRING,4,NULL},
	{"etag",OS210_TYPE_STRING,4,NULL},
	{"curr_time",OS210_TYPE_LONGLONG,sizeof(long long),NULL},
	{"last_time",OS210_TYPE_LONGLONG,sizeof(long long),NULL},
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
#endif
