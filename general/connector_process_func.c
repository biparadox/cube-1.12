#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <dirent.h>
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
#include "../include/connector.h"
#include "../include/logic_baselib.h"
#include "../include/connector.h"
#include "../include/sec_entity.h"
#include "../include/valuename.h"
#include "../include/main_proc_init.h"
#include "../include/expand_define.h"

#include "../cloud_config.h"
#include "connector_process_func.h"

enum  conn_config_attr
{
	CONN_ATTR_DEFAULT=0x01,
	CONN_ATTR_STOP=0x8000,
};

struct  connector_config
{
	char name[DIGEST_SIZE*2];
	int  family;
	int  type;	
	char  *  address;
	int  port;
	int  attr;
};

static NAME2VALUE connector_family_valuelist[] = 
{
	{"AF_INET",AF_INET},
	{"AF_UNIX",AF_UNIX},
	{NULL,0}
};

static NAME2VALUE connector_attr_valuelist[] = 
{
	{"DEFAULT",CONN_ATTR_DEFAULT},
	{"STOP",CONN_ATTR_STOP},
	{NULL,0}
};


static struct struct_elem_attr connector_config_desc[] =
{
    {"name",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
    {"family",OS210_TYPE_ENUM,sizeof(int),&connector_family_valuelist},
    {"type",OS210_TYPE_ENUM,sizeof(int),&connector_type_valuelist},
    {"address",OS210_TYPE_ESTRING,DIGEST_SIZE*2,NULL},
    {"port",OS210_TYPE_INT,sizeof(int),NULL},
    {"attr",OS210_TYPE_ENUM,sizeof(int),&connector_attr_valuelist},
    {NULL,OS210_TYPE_ENDDATA,0,NULL}
};

struct connect_ack
{
	char uuid[DIGEST_SIZE*2];    //client's uuid
	char * client_name;	     // this client's name
	char * client_process;       // this client's process
	char * client_addr;          // client's address
	char server_uuid[DIGEST_SIZE*2];  //server's uuid
	char * server_name;               //server's name
	char * service;
	char * server_addr;              // server's addr
	int flags;
	char nonce[DIGEST_SIZE];
} __attribute__((packed));

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

static void * default_conn=NULL;

struct tcloud_connector * hub_get_connector_byreceiver(void * hub, char * uuid, char * name, char * service)
{
	struct tcloud_connector * this_conn, *temp_conn;
	
	int new_fd;

	temp_conn=hub_get_first_connector(hub);

	while(temp_conn!=NULL)
	{
		this_conn=temp_conn;
		temp_conn=hub_get_next_connector(hub);
		
		if(this_conn->conn_type==CONN_CHANNEL)
		{
			struct connect_proc_info * connect_extern_info;
			connect_extern_info=(struct connect_proc_info *)(this_conn->conn_extern_info);
			if(connect_extern_info==NULL)
				continue;
			if(uuid!=NULL)
			{
				if(strncmp(uuid,connect_extern_info->uuid,64)!=0)
					continue;
			}
			if(name==NULL)
				return this_conn;
			if(strcmp(this_conn->conn_name,name)==0)
				return this_conn;		
		}
		else if(this_conn->conn_type==CONN_CLIENT)
		{
			struct connect_syn * connect_extern_info;
			connect_extern_info=(struct connect_syn *)(this_conn->conn_extern_info);
			if(connect_extern_info==NULL)
				continue;
			if(uuid!=NULL)
			{
				if(strncmp(uuid,connect_extern_info->uuid,64)!=0)
					continue;
			}
			if(name!=NULL)
			{
				if(strncmp(name,connect_extern_info->server_name,64)!=0)
					continue;
			}
			if(service==NULL)
				return this_conn;
			if(strcmp(connect_extern_info->service,service)==0)
				return this_conn;		

		}
	}
	return NULL;
}

void * hub_get_connector_bypeeruuid(void * hub,char * uuid)
{
	int ret;
	int i;
	TCLOUD_CONN * conn;
	BYTE conn_uuid[DIGEST_SIZE*2];

	conn=hub_get_first_connector(hub);
	
	while(conn!=NULL)
	{	

		if(connector_get_type(conn)==CONN_CLIENT)
		{
			struct connect_syn * syn_info=(struct connect_syn *)(conn->conn_extern_info);
			if(syn_info!=NULL)
			{
				comp_proc_uuid(syn_info->uuid,syn_info->server_name,conn_uuid);
				if(strncmp(conn_uuid,uuid,DIGEST_SIZE*2)==0)
					break;
			}

		}
		else if(connector_get_type(conn)==CONN_CHANNEL)
		{
			struct connect_proc_info * channel_info=(struct connect_ack *)(conn->conn_extern_info);
			if(channel_info!=NULL)
			{
				comp_proc_uuid(channel_info->uuid,channel_info->proc_name,conn_uuid);
				if(strncmp(conn_uuid,uuid,DIGEST_SIZE*2)==0)
					break;
			}

		}
		conn=hub_get_next_connector(hub);
	}
	return conn;

}

#define MAX_LINE_LEN 1024
int read_conn_cfg_buffer(FILE * stream, char * buf, int size)
    /*  Read text data from config file,
     *  ignore the ^# line and remove the \n character
     *  stream: the config file stream
     *  buf: the buffer to store the cfg data
     *  size: read data size
     *
     *  return value: read data size,
     *  negative value if it has special error
     *  */
{
    long offset=0;
    long curr_offset;
    char buffer[MAX_LINE_LEN];
    char * retptr;
    int len;

    while(offset<size)
    {
        curr_offset=ftell(stream);
        retptr=fgets(buffer,MAX_LINE_LEN,stream);

        // end of the file
        if(retptr==NULL)
            break;
        len=strlen(buffer);
        if(len==0)
            break;
        // commet line
        if(buffer[0]=='#')
            continue;
        while((buffer[len-1]=='\r')||(buffer[len-1]=='\n'))
        {
            len--;
            if(len==0)
                continue;
            buffer[len]==0;
        }
        // this line is too long to read
        if(len>size)
            return -EINVAL;

        // out of the bound
        if(len+offset>size)
        {
            fseek(stream,curr_offset,SEEK_SET);
            break;
        }
        memcpy(buf+offset,buffer,len);
        offset+=len;
    }
    return offset;
}

int read_one_connector(void ** connector,void * json_node)
{
    void * conn_cfg_template=create_struct_template(&connector_config_desc);
    void * conn_cfg_node;
    void * temp_node;
    char buffer[1024];
    int ret;
    struct connector_config * temp_cfg;


    struct tcloud_connector * conn=NULL;


    if(json_node!=NULL)
    {
        temp_cfg=malloc(sizeof(struct connector_config));
        ret=json_2_struct(json_node,temp_cfg,conn_cfg_template);
        if(ret<0)
            return -EINVAL;
	conn=get_connector(temp_cfg->type,temp_cfg->family);
	if(conn==NULL)
		return -EINVAL;


	switch(temp_cfg->family){
		case AF_INET:
			sprintf(buffer,"%s:%d",temp_cfg->address,temp_cfg->port);
			break;
		default:
			return -EINVAL;
	}

  	ret=conn->conn_ops->init(conn,temp_cfg->name,buffer);
	if(ret<0)
	{
		printf("init conn %s failed!\n",temp_cfg->name);
      		return -EINVAL;
	}

    }

    // read the router policy
    // first,read the main router policy

    *connector=conn;
    if(temp_cfg->attr==CONN_ATTR_DEFAULT)
    {
	    if(default_conn!=NULL)
	    {
		    printf("not unique default conn!\n");
		    return -EINVAL;
	    }
	    default_conn=conn;
    }
    return 0;
}

int connector_read_cfg(char * filename,void * hub)
{
    const int bufsize=4096;
    char buffer[bufsize];
    int read_offset;
    int solve_offset;
    int buffer_left=0;
    int conn_num=0;
    void * conn;
    int ret;
    void * root;
    struct tcloud_connector_hub * conn_hub=(struct tcloud_connector_hub *)hub;
    int i;

    FILE * fp = fopen(filename,"r");
    if(fp==NULL)
        return -EINVAL;

    do {

        // when the file reading is not finished, we should read new data to the buffer
        if(fp != NULL)
        {
            read_offset=read_conn_cfg_buffer(fp,buffer+buffer_left,bufsize-buffer_left);
            if(read_offset<0)
                return -EINVAL;
            else if(read_offset<bufsize-buffer_left)
            {
                fclose(fp);
                fp=NULL;
            }
        }
        printf("conn %d is %.4s\n",conn_num+1,buffer);

        solve_offset=json_solve_str(&root,buffer);
        if(solve_offset<=0)
	{
		if(conn_num>0)
			return conn_num;
           	return -EINVAL;
	}

        ret=read_one_connector(&conn,root);

        if(ret<0)
            return -EINVAL;
        conn_num++;
	conn_hub->hub_ops->add_connector(conn_hub,conn,NULL);
        buffer_left=read_offset-solve_offset;
        if(buffer_left>0)
	{
//	    printf( "3 left conn first char is %c\n",buffer[solve_offset]);
//	    for(i=0;i<buffer_left;i++)
//		buffer[i]=buffer[solve_offset+i];
            Memcpy(buffer,buffer+solve_offset,buffer_left);
	    buffer[buffer_left]=0;
	}
        else
        {
            if(fp==NULL)
                break;
        }
    }while(1);
    return conn_num;
}

void * build_server_syn_message(char * service,char * local_uuid,char * proc_name)
{
	void * message_box;
	struct connect_syn * server_syn;
	MESSAGE_HEAD * message_head;
	void * syn_template;
	BYTE * blob;
	int record_size;
	int retval;

	server_syn=malloc(sizeof(struct connect_syn));
	if(server_syn == NULL)
		return -ENOMEM;

	memset(server_syn,0,sizeof(struct connect_syn));
	
	memcpy(server_syn->uuid,local_uuid,DIGEST_SIZE*2);
	server_syn->server_name=dup_str(proc_name,0);

	if(service!=NULL)
		server_syn->service=dup_str(service,0);
	message_box=message_create("SYNI");
	if(message_box==NULL)
		return -EINVAL;
	if(IS_ERR(message_box))
		return -EINVAL;
	retval=message_add_record(message_box,server_syn);

	printf("init message success!\n");
	return message_box;

}

void * build_client_ack_message(void * message_box,char * local_uuid,char * proc_name,void * conn)
{
	MESSAGE_HEAD * message_head;
	struct connect_ack  * client_ack;
	struct connect_syn  * server_syn;
	int retval;
	void * ack_template;
	int record_size;
	void * blob;
	struct tcloud_connector * temp_conn=conn;

	client_ack=malloc(sizeof(struct connect_ack));
	if(client_ack==NULL)
		return -ENOMEM;
	server_syn=malloc(sizeof(struct connect_syn));
	if(server_syn==NULL)
		return -ENOMEM;

	memset(client_ack,0,sizeof(struct connect_ack));
		// monitor send a new image message
	retval=message_get_record(message_box,&server_syn,0);

	if(retval<0)
		return -EINVAL;
	if(server_syn==NULL)
		return -EINVAL;
	temp_conn->conn_extern_info=server_syn;

	memcpy(client_ack->uuid,local_uuid,DIGEST_SIZE*2);
//	client_ack->client_name=dup_str("unknown machine",0);
	client_ack->client_name=dup_str(proc_name,0);
	client_ack->client_process=dup_str(proc_name,0);
	client_ack->client_addr=dup_str("unknown addr",0);

	memcpy(client_ack->server_uuid,server_syn->uuid,DIGEST_SIZE*2);
	client_ack->server_name=dup_str(server_syn->server_name,0);
	client_ack->service=dup_str(server_syn->service,0);
	client_ack->server_addr=dup_str(server_syn->server_addr,0);
	client_ack->flags=server_syn->flags;
	strncpy(client_ack->nonce,server_syn->nonce,DIGEST_SIZE);

	message_box=message_create("ACKI");
	if(message_box==NULL)
		return -EINVAL;
	if(IS_ERR(message_box))
		return -EINVAL;

	retval=message_add_record(message_box,client_ack);
	printf("create a client ack message!\n");
	return message_box;
}

int receive_local_client_ack(void * message_box,void * conn,void * hub)
{
	MESSAGE_HEAD * message_head;
	struct connect_ack  * client_ack;
	int retval;
	struct tcloud_connector * channel_conn=conn;
	void * ack_template;
	int record_size;
	void * blob;
	struct connect_proc_info * channel_info;


	client_ack=malloc(sizeof(struct connect_ack));
	if(client_ack==NULL)
		return -ENOMEM;
	memset(client_ack,0,sizeof(struct connect_ack));


	channel_info=malloc(sizeof(struct connect_proc_info));
	if(channel_info==NULL)
		return -ENOMEM;
	memset(channel_info,0,sizeof(struct connect_proc_info));
//	channel_info->channel_state=PROC_CHANNEL_RECVACK;
	channel_conn->conn_extern_info=channel_info;

//	retval=load_message_record(message_box,&client_ack);
	retval=message_get_record(message_box,&client_ack,0);

	if(retval<0)
		return -EINVAL;

	channel_conn->conn_ops->setname(channel_conn,client_ack->client_name);

	BYTE conn_uuid[DIGEST_SIZE*2];

	comp_proc_uuid(client_ack->uuid,client_ack->client_process,conn_uuid);

	TCLOUD_CONN * temp_conn=hub_get_connector_bypeeruuid(hub,conn_uuid);
	if(temp_conn!=NULL)
	{
		((TCLOUD_CONN_HUB *)hub)->hub_ops->del_connector(hub,temp_conn);
		temp_conn->conn_ops->disconnect(temp_conn);
	}
	
	memcpy(channel_info->uuid,client_ack->uuid,DIGEST_SIZE*2);
	channel_info->proc_name=dup_str(client_ack->client_process,0);
	channel_info->channel_name=NULL;
	channel_info->islocal=1;
//	channel_info->channel_state=PROC_CHANNEL_READY;
	
	connector_setstate(channel_conn,CONN_CHANNEL_HANDSHAKE);
	return 0;

}


struct connector_proc_pointer
{
	void * hub;
	void * default_local_conn;
	void * default_remote_conn;
};

int proc_conn_init(void * sub_proc,void * para)
{
	int ret;
	struct connector_proc_pointer * sub_proc_pointer;
	struct conn_init_para * conn_init_para = (struct conn_init_para *)para;

	ret=sec_subject_create_statelist(sub_proc, connector_process_state_name);
        if(ret<0)
		return ret;	
	ret=sec_subject_register_statelist(sub_proc,conn_state_list);
        if(ret<0)
		return ret;	

	ret=sec_subject_create_funclist(sub_proc, connector_process_func_name);
        if(ret<0)
		return ret;	
	ret=sec_subject_register_funclist(sub_proc, conn_func_list);
        if(ret<0)
		return ret;	
	register_record_type("SYNI",connect_syn_desc,NULL);
	register_record_type("ACKI",connect_ack_desc,NULL);
	struct tcloud_connector_hub * conn_hub;
 	conn_hub=get_connector_hub();


	void * context;
	ret=sec_subject_getcontext(sub_proc,&context);
	if(ret<0)
		return ret;
	sub_proc_pointer=malloc(sizeof(struct connector_proc_pointer));
	if(sub_proc_pointer==NULL)
		return -ENOMEM;
	memset(sub_proc_pointer,0,sizeof(struct connector_proc_pointer));
	sub_proc_pointer->hub=conn_hub;
	ret=sec_object_setpointer(context,sub_proc_pointer);
	if(ret<0)
		return ret;
	ret=connector_read_cfg("connector_config.cfg",conn_hub);
	if(ret<0)
		return ret;
	printf("read %d connector!\n",ret);

	struct tcloud_connector * temp_conn;

	temp_conn=hub_get_first_connector(conn_hub);
	
	// start all the SERVER

	while(temp_conn!=NULL)
	{
		if(connector_get_type(temp_conn)==CONN_SERVER)
		{
  	 		ret=temp_conn->conn_ops->listen(temp_conn);
			if(ret<0)
			{
				printf("conn server %s listen error!\n",connector_getname(temp_conn));
				return -EINVAL;
			}
			printf("conn server %s begin to listen!\n",connector_getname(temp_conn));

		}	
		temp_conn=hub_get_next_connector(conn_hub);
	}
	return 0;
}


int proc_conn_start(void * sub_proc,void * para)
{
	int ret;
	int retval;
	void * message_box;
	MESSAGE_HEAD * message_head;
	void * context;
	int i,j;
	struct tcloud_connector * temp_conn;
	struct tcloud_connector * recv_conn;
	struct tcloud_connector * send_conn;
	char local_uuid[DIGEST_SIZE*2+1];
	char proc_name[DIGEST_SIZE*2+1];
	struct connector_proc_pointer * sub_proc_pointer;
	
	ret=proc_share_data_getvalue("uuid",local_uuid);
	ret=proc_share_data_getvalue("proc_name",proc_name);


	struct timeval conn_val;
	conn_val.tv_usec=time_val.tv_usec;

	ret = sec_subject_getcontext(sub_proc,&context);
	if(ret<0)
		return ret;

	sub_proc_pointer=sec_object_getpointer(context);

	struct tcloud_connector_hub * hub = sub_proc_pointer->hub;
	if((hub==NULL) || IS_ERR(hub))
		return -EINVAL;

	// start all the CLIENT
	
	temp_conn=hub_get_first_connector(hub);
	
	while(temp_conn!=NULL)
	{
		if(connector_get_type(temp_conn)==CONN_CLIENT)
		{
			for(i=0;i<180;i++)
			{
   				ret=temp_conn->conn_ops->connect(temp_conn);
				if(ret>=0)
				{
					break;
				}
				usleep(50);
			}

		}	
		temp_conn=hub_get_next_connector(hub);
	}

	

	// 

	for(i=0;i<500*1000;i++)
	{

//		usleep(conn_val.tv_usec);

		// receive the remote message
		ret=hub->hub_ops->select(hub,&conn_val);
		usleep(conn_val.tv_usec);
		conn_val.tv_usec=time_val.tv_usec;
		if(ret>0) {

			do{
	
				recv_conn=hub->hub_ops->getactiveread(hub);
				if(recv_conn==NULL)
					break;

				if(connector_get_type(recv_conn)==CONN_SERVER)
				{
	
					struct tcloud_connector * channel_conn;
	
					channel_conn=recv_conn->conn_ops->accept(recv_conn);
					if(channel_conn==NULL)
					{
						printf("error: server connector accept error %x!\n",channel_conn);
						continue;
					}
					connector_setstate(channel_conn,CONN_CHANNEL_ACCEPT);
					printf("create a new channel %x!\n",channel_conn);
 
					// build a server syn message with service name,uuid and proc_name
					message_box=build_server_syn_message("trust_server",local_uuid,proc_name);
					if((message_box == NULL) || IS_ERR(message_box))
					{
						printf("local_server reply syn message error!\n");
						continue;
					}
			
					retval=message_send(message_box,channel_conn);
					if(retval<=0)
						continue;
					hub->hub_ops->add_connector(hub,channel_conn,NULL);
				}
				else if(connector_get_type(recv_conn)==CONN_CLIENT)
				{


					while((ret=message_read_from_conn(&message_box,recv_conn))>0)
					{
						printf("proc conn client receive %d data!\n",ret);

						
						message_head=get_message_head(message_box);

						if(strncmp(message_head->record_type,"SYNI",4)==0)
						// do the handshake	
						{
							void * message=build_client_ack_message(message_box,local_uuid,proc_name,recv_conn);
							if((message == NULL) || IS_ERR(message))
								continue;
							send_conn=recv_conn;
							retval=message_send(message,send_conn);
							connector_setstate(send_conn,CONN_CLIENT_RESPONSE);
							printf("client %s send %d ack data to server !\n",connector_getname(send_conn),retval);
						
						}
						sec_subject_sendmsg(sub_proc,message_box);
					
						continue;		
					}

				}
				else if(connector_get_type(recv_conn)==CONN_CHANNEL)
				{	
					char * sender_uuid;
					char * sender_name;
					char * receiver_uuid;
					char * receiver_name;
					struct expand_data_forward * expand_forward;
			 		struct connect_proc_info * channel_extern_info;

					while(message_read_from_conn(&message_box,recv_conn)>0)
					{

						message_head=get_message_head(message_box);

						// first: finish the handshake
						if(strncmp(message_head->record_type,"ACKI",4)==0)
						{
							ret=receive_local_client_ack(message_box,recv_conn,hub);
							sec_subject_sendmsg(sub_proc,message_box);
							printf("channel set name %s!\n",connector_getname(recv_conn));
							continue;
						}
						// check if this message is for you or for others
						printf("channel receive %4s message from conn %s!\n",message_head->record_type,connector_getname(recv_conn));
						sec_subject_sendmsg(sub_proc,message_box);
						printf("client forward %s message to main proc!\n",message_head->record_type);
						continue;		

					}	
				}

			}while(1);
		}

		// send message to the remote
		while(sec_subject_recvmsg(sub_proc,&message_box)>=0)
		{
			if(message_box==NULL)
				break;
			message_head=get_message_head(message_box);
			if(message_head->flow & MSG_FLOW_LOCAL)
			{
				printf("error local message in conn proc!\n");
				message_free(message_box);
				continue;
			}

			char buffer[DIGEST_SIZE*2+1];

			switch(message_head->receiver_uuid[0])
			{
				case	'@':  // receiver_uuid is receiver's name
					strncpy(buffer,message_head->receiver_uuid+1,DIGEST_SIZE*2-1);
					send_conn=hub_get_connector_byreceiver(sub_proc_pointer->hub,NULL,
						buffer,NULL);	
					break;

				case	':':  // receiver_uuid is connector's name
					strncpy(buffer,message_head->receiver_uuid+1,DIGEST_SIZE*2-1);
					send_conn=hub_get_connector(sub_proc_pointer->hub,buffer);	
					break;
				case    '\0':
					send_conn=default_conn;
					break;
				default:
					send_conn=hub_get_connector_bypeeruuid(sub_proc_pointer->hub,message_head->receiver_uuid);	
					break;
			}

			if(send_conn!=NULL)
			{
				ret=message_send(message_box,send_conn);
				printf("send %4s message %d to conn %s!\n",message_head->record_type,ret,connector_getname(send_conn));
			}
			else
				printf("send %4s message failed: no conn!\n",message_head->record_type);

		}	

	}


	return 0;
};

int proc_conn_accept(void * this_proc,void * msg,void * conn)
{

}

int proc_conn_sync(void * this_proc,void * msg,void * conn)
{

}

int proc_conn_acksend(void * this_proc,void * msg,void * conn)
{

}

int proc_conn_channelbuild(void * this_proc,void * msg,void * conn)
{

}

