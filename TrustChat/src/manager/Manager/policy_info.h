#ifndef POLICY_INFO_H
#define POLICY_INFO_H

struct policy_rule
{
	char proc_name[DIGEST_SIZE];
	int  policy_size;
	char * policy_data;
}__attribute__((packed));

static struct struct_elem_attr policy_rule_desc[]=
{
        {"proc_name",OS210_TYPE_STRING,DIGEST_SIZE,NULL},
        {"policy_size",OS210_TYPE_INT,sizeof(int),NULL},
	{"policy_data",OS210_TYPE_DEFINE,1,"policy_size"},	
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
#endif
