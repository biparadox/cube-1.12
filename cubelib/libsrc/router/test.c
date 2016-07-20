#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include "../include/router.h"
#include "../include/struct_deal.h"

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
char * name[3]={"zhangsongge","taozheng","wangyubo"};
char * passwd[3]={"openstack","openstack","password"};

int main(void)
{
    const char * config_filename= "./router_policy.cfg";
	int i,recordnum;
	int ret;

    void * record;
    void * message;
    void * recv_message;
    void * msg_head;
    int retval;
    struct connect_login * login_info;

    logic_baselib_init();
    register_record_type("LOGC",&connect_login_desc,NULL);

    message=message_create("LOGC",NULL);
    for(i=0;i<3;i++)
    {
        login_info=malloc(sizeof(struct connect_login));
        login_info->user=dup_str(name[i],0);
        login_info->passwd=dup_str(passwd[i],0);
        memset(login_info->nonce,'0',DIGEST_SIZE);
        message_add_record(message,login_info);
    }

    router_policy_init();
    ret=router_read_cfg(config_filename);
    if(ret<0)
      return -EINVAL;
    void * msg_policy;
    ret=router_policy_getfirst(&msg_policy);
    if(ret<0)
    {
        printf("get msg policy failed!\n");
        return -EINVAL;
    }
    printf("get msg policy succeed!\n");
    ret=router_policy_match_message(msg_policy,message,NULL);
    return 0;
}
