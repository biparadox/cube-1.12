#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>


#include "../include/data_type.h"
#include "../include/struct_deal.h"
#include "../include/valuename.h"
#include "../include/extern_struct.h"
#include "../include/extern_struct_desc.h"
#include "../include/message_struct.h"
#include "../include/message_struct_desc.h" 
#include "../include/connector.h"
#include "../include/logic_baselib.h"
#include "../include/vtpm_struct.h"
#include "../include/vtpm_desc.h"
//#include "logic_vtpm.h"

struct expand_flow_trace
{
    int  data_size;
    char tag[4];                 // this should be "FTRE"
    int  record_num;
    char *trace_record;
} __attribute__((packed));

static struct struct_elem_attr expand_flow_trace_desc[] =
{
    {"data_size",OS210_TYPE_INT,sizeof(int),0},
    {"tag",OS210_TYPE_STRING,4,0},
    {"record_num",OS210_TYPE_INT,sizeof(int),0},
    {"trace_record",OS210_TYPE_DEFSTRARRAY,DIGEST_SIZE*2,"record_num"},
    {NULL,OS210_TYPE_ENDDATA,0,NULL}
};
char * local_uuid="local_uuid";
char * proc_name="proc_name";

BYTE Blob[4096];
char text[4096];
/*
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
*/

char * name[3]={"\\\"zhang\\\":\\\"songge\\\"","taozheng","wangyubo"};
char * passwd[3]={"openstack","openstack","password"};

int main()
{
// step 1: make and init buffer database
//
//
	struct struct_elem_attr * test_desc;
	void * struct_template;

	void * record;
    void * message;
    void * recv_message;
    void * msg_head;
	int retval;
    struct connect_login * login_info;
    char * blob;
    int i;

	// step 1.0 init the memdb and register lib
    logic_baselib_init();
    register_record_type("LOGC",&connect_login_desc);
    register_record_type("FTRE",&expand_flow_trace_desc);

	

    message=message_create("LOGC",NULL);
    const char * type;
    type=message_get_recordtype(message);

    for(i=0;i<3;i++)
    {
        login_info=malloc(sizeof(struct connect_login));
      //  login_info->user=dup_str(name[i],0);
      //  login_info->passwd=dup_str(passwd[i],0);
        memset(login_info->nonce,'0',DIGEST_SIZE);
        message_add_record(message,login_info);
    }
    struct expand_flow_trace * expand_forward = malloc(sizeof(struct expand_flow_trace));
    memset(expand_forward,0,sizeof(struct expand_flow_trace));
    memcpy(expand_forward->tag,"FTRE",4);
    expand_forward->record_num=1;
    expand_forward->trace_record=malloc(DIGEST_SIZE*2*expand_forward->record_num);
    memcpy(expand_forward->trace_record,"test_sender",12);
    message_add_expand(message,expand_forward);

    void * new_msg=message_clone(message);
    retval=message_output_blob(message,&blob);

    retval=message_read_from_blob(&recv_message,blob,retval);
    message_load_record(recv_message);
    message_load_expand(recv_message);

    message_free(recv_message);

    int fd;
    fd=open("test.blb",O_WRONLY|O_CREAT|O_TRUNC,S_IRWXU);
    if(fd<0)
        return -EINVAL;
    write(fd,blob,retval);
    close(fd);
    fd=open("test.blb",O_RDONLY);
    if(fd<0)
        return -EINVAL;

    retval=message_read_from_src(&recv_message,fd,read);
    message_load_record(recv_message);
    message_load_expand(recv_message);

    retval=message_2_json(recv_message,text);
    printf("%s\n",text);

    message_free(message);

    retval=json_2_message(text,&message);

    for(i=0;i<3;i++)
    {
        retval=message_get_record(message,&login_info,i);
        printf("%s %s\n",login_info->user,login_info->passwd);
    }

}

