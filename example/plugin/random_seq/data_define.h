#ifndef USER_INFO_H
#define USER_INFO_H
#include <time.h>

enum data_type
{
	DATA_INIT=0x01,
	DATA_ADD=0x02,
	DATA_DEL=0x03,
	DATA_INSERT=0x04,
	DATA_SWAP=0x05,
	DATA_RESULT=0x06,
	DATA_ERROR=0xFF,
};
static NAME2VALUE data_type_valuelist[] =
{
	{"INIT",DATA_INIT},
	{"ADD",DATA_ADD},
	{"DEL",DATA_DEL},
	{"INSERT",DATA_INSERT},
	{"SWAP",DATA_SWAP},
	{"RESULT",DATA_RESULT},
	{"ERROR",DATA_ERROR},
	{NULL,0}
};


struct visual_data
{
	enum data_type type;
	int  index;
	char * name;
	int  value;
}__attribute__((packed));

static struct struct_elem_attr visual_data_desc[]=   // INTD
{
        {"type",OS210_TYPE_ENUM,sizeof(int),&data_type_valuelist},
        {"index",OS210_TYPE_INT,sizeof(int),NULL},
        {"name",OS210_TYPE_ESTRING,DIGEST_SIZE,NULL},
        {"value",OS210_TYPE_INT,sizeof(int),NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

#endif
