#ifndef USER_INFO_H
#define USER_INFO_H

enum user_state_type
{
	USER_ADMIN=0x01,
	USER_GENERAL=0x02,
	USER_BLOCK=0x03,
	USER_ERROR=0xFF,
};

struct user_info_list{
	char name[DIGEST_SIZE];
	BYTE passwd[DIGEST_SIZE];
	int  register_time;
	enum  user_state_type state;
};

static NAME2VALUE user_state_type_valuelist[] =
{
	{"ADMIN",USER_ADMIN},
	{"GENERAL",USER_GENERAL},
	{"BLOCK",USER_BLOCK},
	{NULL,0}
	
};

static struct struct_elem_attr user_info_list_desc[]=
{
        {"name",OS210_TYPE_STRING,DIGEST_SIZE,NULL},
        {"passwd",OS210_TYPE_STRING,DIGEST_SIZE,NULL},
        {"register_time",OS210_TYPE_TIME,sizeof(int),NULL},
        {"state",OS210_TYPE_ENUM,sizeof(int),&user_state_type_valuelist},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

struct login_info
{
	char user[DIGEST_SIZE];
	char passwd[DIGEST_SIZE];
	char nonce[DIGEST_SIZE];
} __attribute__((packed));

static struct struct_elem_attr login_info_desc[]=
{
	{"user",OS210_TYPE_STRING,DIGEST_SIZE,NULL},
	{"passwd",OS210_TYPE_STRING,DIGEST_SIZE,NULL},
	{"nonce",OS210_TYPE_BINDATA,DIGEST_SIZE,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
struct user_name_expand
{
	int data_size;
	char tag[4];
	char name[DIGEST_SIZE];
};

static struct struct_elem_attr user_name_expand_desc[]=
{
	{"data_size",OS210_TYPE_INT,sizeof(int),0},
	{"tag",OS210_TYPE_STRING,4,0},
	{"name",OS210_TYPE_STRING,DIGEST_SIZE,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

#endif
