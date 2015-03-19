#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "../include/data_type.h"
#include "../include/struct_deal.h"
#include "../include/crypto_func.h"
#include "../include/extern_struct.h"
#include "../include/extern_defno.h"
#include "../include/message_struct.h"
#include "../include/vmlist.h"
#include "../include/vm_policy.h"
#include "../include/connector.h"
#include "../include/logic_baselib.h"
#include "../include/connector.h"
#include "../include/sec_entity.h"

#include "../../cloud_config.h"
#include "json_port_func.h"

static char local_jsonserver_addr[] = "0.0.0.0:12888";

struct json_server_context
{
       void * json_port_hub;  //interface's hub
       void * syn_template;
       void * connect_syn;
       char * json_message;
       int message_len;
};

struct connect_syn
{
	char uuid[DIGEST_SIZE*2];
	char * server_name;
	char * service;
	char * server_addr;
	int  flags;
	char nonce[DIGEST_SIZE];
}__attribute__((packed));

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

int json_port_init(void * sub_proc,void * para)
{
	int ret;
    struct json_server_context * sub_context;
    struct message_box * msg_box;
    struct message_box * new_msg;
    struct tcloud_connector_hub * port_hub;

    MESSAGE_HEAD * msg_head;

    char local_uuid[DIGEST_SIZE*2+1];
    char proc_name[DIGEST_SIZE*2+1];
 	
    ret=proc_share_data_getvalue("uuid",local_uuid);
    if(ret<0)
	    return ret;
    ret=proc_share_data_getvalue("proc_name",proc_name);
    register_record_type("SYNI",connect_syn_desc,NULL);

    // process init
    sec_subject_register_statelist(sub_proc,json_server_state_list);
    ret=sec_subject_create_statelist(sub_proc, json_server_state_list);
    if(ret<0)
        return ret;
    sub_context=malloc(sizeof(struct json_server_context));
    if(sub_context==NULL)
        return -ENOMEM;
    memset(sub_context,0,sizeof(struct json_server_context));

    void * context;
    ret=sec_subject_getcontext(sub_proc,&context);
    if(ret<0)
         return ret;
    sec_object_setpointer(context,sub_context);

    // parameter deal with
    char * server_name="json_server";
    char * server_uuid=local_uuid;
    char * service=sec_subject_getname(sub_proc);
    char * server_addr=local_jsonserver_addr;
    char * nonce="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    struct connect_syn * syn_info;
    syn_info=malloc(sizeof(struct connect_syn));
    if(syn_info==NULL)
        return -ENOMEM;
    memset(syn_info,0,sizeof(struct connect_syn));

    char buffer[1024];
    memset(buffer,0,1024);

    int stroffset=0;

    msg_box=build_server_syn_message(service,local_uuid,proc_name);  
    stroffset=message_2_json(msg_box,buffer);
    printf("json message size is %d\n",stroffset);
    printf("json message:%s\n",buffer);

    ret=json_2_message(buffer,&new_msg);
    if(ret<0)
        return -EINVAL;

    sub_context->json_message=dup_str(buffer,0);
    sub_context->message_len=strlen(buffer);

    port_hub=get_connector_hub();

    sub_context->json_port_hub=port_hub;
    struct tcloud_connector * temp_conn;

    temp_conn=get_connector(CONN_SERVER,AF_INET);
    if((temp_conn ==NULL) || IS_ERR(temp_conn))
    {
            printf("get json server conn failed!\n");
            return -EINVAL;
    }

    ret=temp_conn->conn_ops->init(temp_conn,server_name,server_addr);
    if(ret<0)
    {
           printf("init conn json_server failed!\n");
           return -EINVAL;
    }
    port_hub->hub_ops->add_connector(port_hub,temp_conn,NULL);
    ret=temp_conn->conn_ops->listen(temp_conn);
    if(ret<0)
         return -EINVAL;

	return 0;
}

int json_port_start(void * sub_proc,void * para)
{
    int ret;
    int retval;
    void * message_box;
    void * context;
    struct tcloud_connector_hub * port_hub;
    struct tcloud_connector * port_conn;
    struct tcloud_connector * recv_conn;
    struct tcloud_connector * channel_conn;
    int i;
    struct timeval conn_val;
    conn_val.tv_usec=time_val.tv_usec;

    char local_uuid[DIGEST_SIZE*2+1];
    char proc_name[DIGEST_SIZE*2+1];
    char buffer[4096];
    memset(buffer,0,4096);
    int stroffset;
	
    printf("begin json server process!\n");
    ret=proc_share_data_getvalue("uuid",local_uuid);
    if(ret<0)
        return ret;
    ret=proc_share_data_getvalue("proc_name",proc_name);

    if(ret<0)
	return ret;
    struct json_server_context * server_context;

    ret=sec_subject_getcontext(sub_proc,&context);
    server_context=sec_object_getpointer(context);

    port_hub=server_context->json_port_hub;

    port_conn=hub_get_connector(server_context->json_port_hub,"json_server");
    if(port_conn==NULL)
        return -EINVAL;

    channel_conn=NULL;
    for(i=0;i<500*1000;i++)
    {
        ret=port_hub->hub_ops->select(port_hub,&conn_val);
        usleep(conn_val.tv_usec);
	conn_val.tv_usec=time_val.tv_usec;
        if(ret>0)
        {

        	do{

           	 	recv_conn=port_hub->hub_ops->getactiveread(port_hub);
        		if(recv_conn==NULL)
                		break;
          		if(connector_get_type(recv_conn)==CONN_SERVER)
            		{

           		     channel_conn=recv_conn->conn_ops->accept(recv_conn);
         		     if(channel_conn==NULL)
                	     {
              			      printf("error: json_server connector accept error %x!\n",channel_conn);
               			      continue;
               		     }
              		     printf("create a new channel %x!\n",channel_conn);

           		     // build a server syn message with service name,uuid and proc_name
           		     channel_conn->conn_ops->write(channel_conn,
                             	  server_context->json_message,
                              	  server_context->message_len);

               		    port_hub->hub_ops->add_connector(port_hub,channel_conn,NULL);
            		}
	  		else if(connector_get_type(recv_conn)==CONN_CHANNEL)
	    		{
				char * buffer=malloc(65535);
		 		int offset=0;
		  		do {
		 			ret=recv_conn->conn_ops->read(recv_conn,buffer+offset,4096);
		   	 		if(ret<0)
				 		break;
			  		offset+=ret;
		    		}while(ret==4096);
	    	 		void * message;
	    	  		ret=json_2_message(buffer,&message);
		   		if(ret>=0)
		    		{
	    	    			sec_subject_sendmsg(sub_proc,message);	
		    		}
	    		}
		}while(1);
	}
	// send message to the remote
	while(sec_subject_recvmsg(sub_proc,&message_box)>=0)
	{
		if(message_box==NULL)
			break;
    		stroffset=message_2_json(message_box,buffer);
		if(channel_conn!=NULL)
		{
                	channel_conn->conn_ops->write(channel_conn,
                               buffer,stroffset);
		}	
	}

    }
    return 0;
}
