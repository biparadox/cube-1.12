#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>
#include <libwebsockets.h>

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

#include "websocket_func.h"
#include "../cloud_config.h"
//#include "main_proc_func.h"


struct websocket_server_context
{
       void * server_context;  //interface's hub
       void * callback_context;
       void * callback_interface;
       void * syn_template;
       void * connect_syn;
       char * websocket_message;
       int message_len;
       BYTE *read_buf;
       int  readlen;
       BYTE *write_buf;
       int  writelen;
};


static struct websocket_server_context * ws_context;  

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

static int callback_http(	struct libwebsocket_context * this,
				struct libwebsocket * wsi,
				enum libwebsocket_callback_reasons reason,
				void * user,void * in,size_t len)
{
	return 0;
}
		
static int callback_cube_wsport(	struct libwebsocket_context * this,
				struct libwebsocket * wsi,
				enum libwebsocket_callback_reasons reason,
				void * user,void * in,size_t len)
{
	int i;
	switch(reason) {
		case LWS_CALLBACK_ESTABLISHED:
			ws_context->callback_interface=wsi;
			ws_context->callback_context=this;
			printf("connection established\n");
			BYTE * buf= (unsigned char *)malloc(
				LWS_SEND_BUFFER_PRE_PADDING+
				ws_context->message_len+
				LWS_SEND_BUFFER_POST_PADDING);
			if(buf==NULL)
				return -EINVAL;			
			memcpy(&buf[LWS_SEND_BUFFER_PRE_PADDING],
				ws_context->websocket_message,
				ws_context->message_len);
			libwebsocket_write(wsi,
				&buf[LWS_SEND_BUFFER_PRE_PADDING],
				ws_context->message_len,LWS_WRITE_TEXT);
			free(buf);
			break;
		case LWS_CALLBACK_RECEIVE:
		{
			ws_context->read_buf = (unsigned char *)malloc(len);
			if(ws_context->read_buf==NULL)
				return -EINVAL;
			ws_context->readlen=len;
			memcpy(ws_context->read_buf,in,len);
			break;
		}
		default:
			break;
	}
	return 0;
}

static struct libwebsocket_protocols protocols[] = {
	{
		"http_only",
		callback_http,
		0	
	},
	{
		"cube-wsport",
		callback_cube_wsport,
		0
	},
	{
		NULL,NULL,0
	}
};

int websocket_port_init(void * sub_proc,void * para)
{

    int ret;
    struct libwebsocket_context * context;
    struct lws_context_creation_info info;
		

    struct message_box * msg_box;
    struct message_box * new_msg;

    MESSAGE_HEAD * msg_head;

    char local_uuid[DIGEST_SIZE*2+1];
    char proc_name[DIGEST_SIZE*2+1];
 	
    ret=proc_share_data_getvalue("uuid",local_uuid);
    if(ret<0)
	    return ret;
    ret=proc_share_data_getvalue("proc_name",proc_name);
    register_record_type("SYNI",connect_syn_desc);

    ws_context=malloc(sizeof(struct websocket_server_context));
    if(ws_context==NULL)
	return -ENOMEM;
    memset(ws_context,0,sizeof(struct websocket_server_context));

    memset(&info,0,sizeof(info));
    info.port=websocket_port;
//    info.iface=NULL;
    info.iface=websocketserver_addr;
    info.protocols=protocols;
    info.extensions=libwebsocket_get_internal_extensions();
    info.ssl_cert_filepath=NULL;
    info.ssl_private_key_filepath=NULL;
    info.gid=-1;
    info.uid=-1;
    info.options=0;

    // parameter deal with
    char * server_name="websocket_server";
    char * server_uuid=local_uuid;
    char * service=sec_subject_getname(sub_proc);
    char * server_addr=websocketserver_addr;
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
    printf("websocket message size is %d\n",stroffset);
    printf("websocket message:%s\n",buffer);

    ret=json_2_message(buffer,&new_msg);
    if(ret<0)
        return -EINVAL;

    ws_context->websocket_message=dup_str(buffer,0);
    ws_context->message_len=strlen(buffer);

    context = libwebsocket_create_context(&info);
    if(context==NULL)
    {
	printf(" wsport context create error!\n");
	return -EINVAL;
    }
    ws_context->server_context=context;

    return 0;
}

int websocket_port_start(void * sub_proc,void * para)
{
    int ret;
    int retval;
    void * message_box;
    void * context;
    int i;
    struct timeval conn_val;
    conn_val.tv_usec=time_val.tv_usec;

    char local_uuid[DIGEST_SIZE*2+1];
    char proc_name[DIGEST_SIZE*2+1];
    char buffer[4096];
    memset(buffer,0,4096);
    int stroffset;
	
    printf("begin websocket server process!\n");
    ret=proc_share_data_getvalue("uuid",local_uuid);
    if(ret<0)
        return ret;
    ret=proc_share_data_getvalue("proc_name",proc_name);

    if(ret<0)
	return ret;

    printf("starting wsport server ...\n");

    for(i=0;i<500*1000;i++)
    {
	 libwebsocket_service(ws_context->server_context,50);
	 // check if there is something to read
	 if(ws_context->readlen>0)
	{
		int offset=0;
		do {
	    	 	void * message;
			ret=json_2_message(ws_context->read_buf+offset,&message);
		   	if(ret>=0)
		    	{
				if(message_get_state(message)==0)
					message_set_state(message,MSG_FLOW_INIT);
				set_message_head(message,"sender_uuid",local_uuid);
	    	    		sec_subject_sendmsg(sub_proc,message);	
				offset+=ret;
				if(ws_context->readlen-offset<sizeof(MESSAGE_HEAD))
				{
					ws_context->readlen=0;
					break;
				}
		    	}
			else
			{
				printf("resolve websocket message failed!\n");
				ws_context->readlen=0;
				break;
			}
		}while(1);
	}
	// send message to the remote
	while(sec_subject_recvmsg(sub_proc,&message_box)>=0)
	{
		if(message_box==NULL)
			break;
    		stroffset=message_2_json(message_box,buffer+LWS_SEND_BUFFER_PRE_PADDING);
		if(stroffset>0)
			libwebsocket_write(ws_context->callback_interface,
				&buffer[LWS_SEND_BUFFER_PRE_PADDING],
				stroffset,LWS_WRITE_TEXT);

	}

    }
    return 0;
}
