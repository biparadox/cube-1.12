#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "../include/data_type.h"
#include "../include/struct_deal.h"
#define DIGEST_SIZE 32

struct connect_login
{
    char * user;
    char * passwd;
    char nonce[DIGEST_SIZE];
} __attribute__((packed));

static struct struct_elem_attr connect_login_desc[]=
{
    {"user",OS210_TYPE_ESTRING,0,NULL},
    {"passwd",OS210_TYPE_ESTRING,0,NULL},
    {"nonce",OS210_TYPE_BINDATA,DIGEST_SIZE,NULL},
    {NULL,OS210_TYPE_ENDDATA,0,NULL}
};

//the descriptiong struct of pcr selection
static struct struct_elem_attr tcm_pcr_selection_desc[]=
{
	{"size_of_select",OS210_TYPE_USHORT,sizeof(short),NULL},
	{"pcr_select",OS210_TYPE_DEFINE,sizeof(unsigned char),"size_of_select"},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

//the description struct of pcr set
static struct struct_elem_attr tcm_pcr_set_desc[]=
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"trust_level",OS210_TYPE_INT,sizeof(UINT32),NULL},
	{"pcr_select",OS210_TYPE_ORGCHAIN,0,tcm_pcr_selection_desc},
	{"value_size",OS210_TYPE_INT,sizeof(UINT32),NULL},
	{"pcr_value",OS210_TYPE_DEFINE,sizeof(BYTE),"value_size"},
	{"policy_describe",OS210_TYPE_ESTRING,0,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static char * test_str=
   "{\"RECORD\": [{\"passwd\": \"openstack\", \"user\": \"\{zhangsongge\}\"}],"
  "\"HEAD\":{\"sender_uuid\":\"interface_server\",\"receiver_uuid\":\"python_interface\", \"type\": \"LOGC\"},"
   "\"EXPAND\":\"\",}";

static char * test_str1= "{\"target_name\":\"{\\\"uuid\\\":\\\"DEFINE\\\",\\\"compute_monitor\\\":\\\"NAME\\\"}\"";
int main()
{
    void * root;
    int offset;
    struct connect_login  login_info;

    offset=json_solve_str(&root,test_str1);
    offset=json_solve_str(&root,test_str);

    void * head_node;
    void * record_node;
    void * data_node;
    void * type_node;
  
    char  buffer[1024];

    void * struct_template=create_struct_template(tcm_pcr_set_desc);
    struct_template=create_struct_template(connect_login_desc);
   	
    head_node=find_json_elem("HEAD",root);
    if(head_node!=NULL)
    {
           printf("get head node success!\n");
	    	

           type_node=find_json_elem("type",head_node);
	   if(type_node!=NULL)
                 printf  ("get type node success!\n");
	   
    }
    data_node=find_json_elem("RECORD",root);
    if(data_node!=NULL)
    {
	  record_node=get_first_json_child(data_node);

	 if(record_node!=NULL)
     {
         	  printf("get record node success!\n");
             json_2_struct(record_node,&login_info,struct_template);
      }
    }

   printf("%s\n",login_info.user);

    memset(login_info.nonce,'\0',DIGEST_SIZE);

   offset=0;
    struct_2_json(&login_info,buffer,struct_template,&offset);

    printf("recover the data json str %s!\n",buffer);
    return offset;
}
