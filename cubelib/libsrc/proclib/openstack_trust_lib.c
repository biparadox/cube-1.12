#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#ifndef WINDOWS_COMP
#include <sys/types.h>
#include <sys/time.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#else
#include <windows.h>
#include <winsock.h>
#include <winsock2.h>
 #endif
#include <sys/stat.h>
#include <pthread.h>

#include "../include/data_type.h"
#include "../include/kernel_comp.h"
#include "../include/list.h"
#include "../include/attrlist.h"
#include "../include/struct_deal.h"
#include "../include/extern_defno.h"
#include "../include/extern_struct.h"
#include "../include/message_struct.h"
#include "../include/connector.h"
#include "../include/logic_baselib.h"
#include "../include/policy_ui.h"
#include "../include/vm_policy.h"
#include "../include/vmlist.h"
#include "../include/vtpm_struct.h"
#include "../include/vtpm_desc.h"
#include "../include/openstack_trust_lib.h"
#include "../include/valuename.h"
#include "../include/expand_define.h"
#include "../include/extern_struct_desc.h"
#include "../include/message_struct_desc.h" 
#include "../include/vm_policy_desc.h"
#include "../include/vmlist_desc.h"
#pragma comment(lib, "\\lib\\libstruct.a")
//the descriptiong struct of keyfile
/*
static struct struct_elem_attr verify_info_desc[]=
{
        {"verify_data_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
        {"entity_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
        {"policy_type",OS210_TYPE_STRING,4,NULL},
        {"trust_level",OS210_TYPE_INT,sizeof(int),NULL},
        {"info_len",OS210_TYPE_INT,sizeof(int),NULL},
        {"info",OS210_TYPE_ESTRING,0,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
*/
struct proc_share_data
{
	pthread_rwlock_t rwlock;
	int state;
	int count;
	void * temp_pointer;
	void * struct_template;
	void * share_data;
}  * proc_share;

int proc_share_data_init(struct struct_elem_attr * share_data_desc)
{
	int ret;
	proc_share=malloc(sizeof(struct proc_share_data));
	if(proc_share==NULL)
		return -ENOMEM;
	memset(proc_share,0,sizeof(struct proc_share_data));

	proc_share->struct_template=create_struct_template(share_data_desc);
	if((proc_share->struct_template == NULL)
		&& IS_ERR(proc_share->struct_template))
		return -EINVAL;
	ret=alloc_struct(&(proc_share->share_data),proc_share->struct_template);	
	if(ret<0)
		return ret;
	ret=pthread_rwlock_init(&(proc_share->rwlock),NULL);
	if(ret<0)
	{
		free_struct(proc_share->share_data,proc_share->struct_template);
		return -EINVAL;
	}
	ret=sec_object_list_init();
	if(ret<0)
		return -EINVAL;
	ret=sec_subject_list_init();
	if(ret<0)
		return -EINVAL;
	return 0;
}

int proc_share_data_reset()
{
	int ret;
	void * share_data;
	void * struct_template;

	pthread_rwlock_wrlock(&(proc_share->rwlock));
	proc_share->state = -1;
	share_data=proc_share->share_data;
	struct_template=proc_share->struct_template;
	proc_share->share_data=NULL;
	proc_share->struct_template=NULL;
	proc_share->temp_pointer=NULL;
	pthread_rwlock_unlock(&(proc_share->rwlock));

	if(share_data!=NULL)
		free_struct(share_data,struct_template);
	if(struct_template!=NULL)
		free_struct_template(proc_share->struct_template);
	return 0;
}

int proc_share_data_destroy()
{
	int ret;
	proc_share_data_reset();
	ret=pthread_rwlock_destroy(&(proc_share->rwlock));
	if(ret<0)
		return ret;
	free(proc_share);
	proc_share=NULL;
	return 0;
}

int proc_share_data_getstate()
{
	int state;
	if(proc_share==NULL)
		return -1;
	pthread_rwlock_rdlock(&(proc_share->rwlock));
	state=proc_share->state;
	pthread_rwlock_unlock(&(proc_share->rwlock));
	return state;
}

int proc_share_data_setstate(int state)
{
	if(proc_share==NULL)
		return -1;
	pthread_rwlock_wrlock(&(proc_share->rwlock));
	proc_share->state=state;
	pthread_rwlock_unlock(&(proc_share->rwlock));
	return state;
}


void * proc_share_data_getpointer()
{
	void * pointer;
	if(proc_share==NULL)
		return -1;
	pthread_rwlock_rdlock(&(proc_share->rwlock));
	pointer=proc_share->temp_pointer;
	pthread_rwlock_unlock(&(proc_share->rwlock));
	return pointer;
}
int proc_share_data_setpointer(void * pointer)
{
	if(proc_share==NULL)
		return -1;
	pthread_rwlock_wrlock(&(proc_share->rwlock));
	proc_share->temp_pointer=pointer;
	pthread_rwlock_unlock(&(proc_share->rwlock));
	return 0;
}

int proc_share_data_getvalue(char * valuename,void * value)
{
	int ret;
	if(proc_share==NULL)
		return -EINVAL;
	
	pthread_rwlock_wrlock(&(proc_share->rwlock));
	ret=struct_read_elem(valuename,proc_share->share_data,value,proc_share->struct_template);
	pthread_rwlock_unlock(&(proc_share->rwlock));
	return ret;

}
 
int proc_share_data_setvalue(char * valuename,void * value)
{
	int ret;
	if(proc_share==NULL)
		return -EINVAL;
	pthread_rwlock_wrlock(&(proc_share->rwlock));
	ret=struct_write_elem(valuename,proc_share->share_data,value,proc_share->struct_template);
	pthread_rwlock_unlock(&(proc_share->rwlock));
	return ret;
}

static NAME2POINTER record_type_struct[] = 
{

	{"SYNI",connect_syn_desc},
	{"ACKI",connect_ack_desc},

//	{"IMGI",image_info_desc},
//	{"VM_I",vminfo_desc},
//	{"PLAI",platform_info_desc},
//	{"PCRI",tcm_pcr_set_desc},

//	{"VM_P",vm_policy_desc},
//	{"IMGP",vm_policy_desc},
//	{"PLAP",vm_policy_desc},
//	{"PCRP",tcm_pcr_set_desc},
//	{"FILP",policy_file_desc},

//	{"USRT",vtpm_info_desc},
//	{"PLAT",vtpm_info_desc},
//	{"VM_T",vtpm_info_desc},

//	{"PUBK",publickey_desc},
//	{"BLBK",wrappedkey_desc},

//	{"KEYD",keyfile_data_desc},
	{"FILD",policyfile_data_desc},

//	{"IDEE",expand_data_identity_desc},
//	{"FORE",expand_data_forward_desc},

//	{"LOGC",connect_login_desc},
//	{"RETC",connect_return_desc},
//	{"REQC",request_cmd_desc},

//	{"OUSI",openstack_user_desc},
//	{"OPRI",openstack_project_desc},
//	{"VERI",verify_info_desc},
	{NULL,NULL}
};


int openstack_trust_lib_init()
{
	int retval;
	int i=0;
	logic_baselib_init();
	struct struct_elem_attr * record_desc;
	while(record_type_struct[i].name != NULL)
	{
		retval=	register_record_type(record_type_struct[i].name,record_type_struct[i].pointer);
		if(retval<0)
			return retval;
		i++;
	}
	return 0;
}

int message_read_from_conn(void ** message,void * conn)
{
	const int fixed_buf_size=4096;
	char readbuf[fixed_buf_size];
	void * message_box;
	MESSAGE_HEAD * message_head;
	int offset=0;
	int ret;
	int retval;
	int flag;
	struct tcloud_connector * temp_conn=conn;
	int message_size;

	ret=message_read_from_src(message,conn,temp_conn->conn_ops->read);
	if(ret<=0)
		return ret;
	offset=ret;
 
	flag=message_get_flag(*message);
	if(!(flag&MSG_FLAG_CRYPT))
	{
		ret=message_load_record(*message);
		if(ret<0)
		{
			printf("load record failed in message_read_from_conn! use bin format\n");
		}
	}

//	ret=message_free_blob(*message);
	
	ret=message_load_expand(*message);
	
	return offset;           // all the message's data are read
}

/*
int message_forward(void * message,void * conn)
{
	char * blob_size;
	struct message_box * msg_box = message;
	MESSAGE_HEAD * message_head;
	int retval;
	struct tcloud_connector * temp_conn=conn;
	message_head=get_message_head(message);
	if((message_head == NULL) || IS_ERR(message_head))
		return -EINVAL;
	blob_size=sizeof(MESSAGE_HEAD)+message_head->record_size+message_head->expand_size;
	return temp_conn->conn_ops->write(temp_conn,message_get_blob(msg_box),blob_size);
}

*/
int message_send(void * message,void * conn)
{
	int retval;
	BYTE * blob;
	struct tcloud_connector * temp_conn=conn;
	int record_size=message_output_blob(message,&blob);	
	if(record_size<=0)
		return record_size;
	retval=temp_conn->conn_ops->write(temp_conn,blob,record_size);
		printf("send %d data to conn!\n",record_size);
//	message_free(message);
//	free(blob);			
	return retval;
}

int create_internal_return_message(int retval,void ** msg)
{
	void * msg_box;
	struct connect_return * return_data;
    	BYTE writebuf[1024];
	int record_size;
	void * struct_template;

	msg_box=message_create("RETC",NULL);		
	if((msg_box ==NULL) || IS_ERR(msg_box))
		return -EINVAL;
	return_data=malloc(sizeof(struct connect_return));
	if(return_data==NULL)
		return -ENOMEM;
	memset(return_data,0,sizeof(struct connect_return));
	return_data->retval=retval;
  	struct_template=load_record_template("RETC");
	record_size=struct_2_blob(return_data,writebuf,struct_template);

	char uuid[DIGEST_SIZE*2];
	char proc_name[DIGEST_SIZE*2+16];
	int record_num=1;

	proc_share_data_getvalue("uuid",uuid);	
	proc_share_data_getvalue("proc_name",proc_name);	
	set_message_head(msg_box,"record_num",&record_num);
	set_message_head(msg_box,"record_type",(void *)"RETC");
 	set_message_head(msg_box,"sender_uuid",uuid);
 	set_message_head(msg_box,"sender_name",proc_name);
 	set_message_head(msg_box,"receiver_uuid",uuid);
 	set_message_head(msg_box,"receiver_name",proc_name);
	message_add_record_blob(msg_box,record_size,writebuf);
//	add_message_record(msg_box,record_size,0,writebuf);
	*msg=msg_box;
	return 0;		
}

int find_conn_with_expand(void * hub, void * expand,void ** conn)
{
	MESSAGE_HEAD * message_head;
	int retval;
	struct tcloud_connector * channel_conn;
	struct connect_proc_info * channel_info;

	struct expand_data_conn * expand_conn=(struct expand_data_conn *)expand;

	*conn=NULL;

	if(strncmp(expand_conn->tag,"CONE",4)!=0)
		return -EINVAL;

	switch(expand_conn->conn_type)
	{
		case CONN_SERVER:
		case CONN_CLIENT:
			*conn=hub_get_connector(hub,expand_conn->conn_name);
			break;
		case CONN_CHANNEL:
			*conn=general_hub_get_connector(hub,expand_conn->conn_uuid,expand_conn->conn_proc);
			break;
		default:
			return -EINVAL;
	}

	return 0;
}

void * process_return_cmd(void * message) 
{
           MESSAGE_HEAD * message_head;
	   struct message_box * message_box=(struct message_box * )message;
	   struct connect_return * return_data; 
	   int ret;

           message_head=get_message_head(message_box);
           if(strncmp(message_head->record_type,"RETC",4)!=0)
		   return -EINVAL;
           return_data=(struct connect_return *)malloc(sizeof(struct connect_return));
          if(return_data==NULL)
       		  return -ENOMEM;
           ret=message_get_record(message_box,&return_data,0);
           if(ret<0)
                return -EINVAL;
	   return return_data;
}

int build_filedata_struct( void ** filedata,char * filename)
{
        struct policyfile_data *pfdata;
        char digest[DIGEST_SIZE];
        char uuid[DIGEST_SIZE*2];
        FILE *fp;
        BYTE *blob;
        int fd,data_size;
        void *pfdata_template;
        struct stat statbuf;
        int retval;

        //the followin is the creation of data part of message_box
        pfdata=malloc(sizeof(struct policyfile_data));
	if(pfdata==NULL)
	{
		return NULL;
	}
        memset(pfdata,0,sizeof(struct policyfile_data));

        calculate_sm3(filename,digest);
        digest_to_uuid(digest,uuid);
        strncpy(pfdata->uuid,uuid,64);

        pfdata->filename=dup_str(filename,0);
        //pfdata->total_size=strlen(filename);
        pfdata->record_no=0;
        pfdata->offset=0;


        fd=open(filename,O_RDONLY);
        if(fd<0)
        {
	       printf("can't open blob of VM file!\n");
                return NULL;
        }
        if(fstat(fd,&statbuf)<0)
        {
                printf("fstat error\n");
                return NULL;
        }
        data_size=statbuf.st_size;
        pfdata->total_size=data_size;
        pfdata->data_size=data_size;

	pfdata->policy_data=(char *)malloc(sizeof(char)*data_size);

        if(read(fd,pfdata->policy_data,data_size)!=data_size)
        {
                printf("read vm list error! \n");
                return NULL;
        }
	*filedata =pfdata;
        return 1;
}

int get_filedata_from_message(void * message)
{
	struct policyfile_data * pfdata;
	int retval;
	MESSAGE_HEAD * message_head;
	int fd;
        char digest[DIGEST_SIZE];
        char uuid[DIGEST_SIZE*2];

	pfdata= malloc(sizeof(struct policyfile_data));
        if(pfdata==NULL)
       		return -ENOMEM;	       
	message_head=get_message_head(message);
	if(message_head==NULL)
		return -EINVAL;
	
	if(strncmp(message_head->record_type,"FILD",4)!=0)
	{
		return -EINVAL;
	}
	retval=message_get_record(message,&pfdata,0);

	fd=open(pfdata->filename,O_RDONLY);
	if(fd>0)
	{
		printf("file %s has existed!\n",pfdata->filename);
		return -EEXIST;
	}

	fd=open(pfdata->filename,O_CREAT|O_WRONLY|O_TRUNC,0666);
	if(fd<0)
		return fd;
	lseek(fd,pfdata->offset,SEEK_SET);
	write(fd,pfdata->policy_data,pfdata->data_size);
	close(fd);
	if(pfdata->offset+pfdata->data_size==pfdata->total_size)
	{
		retval=calculate_sm3(pfdata->filename,digest);
		if(retval<0)
			return retval;
		digest_to_uuid(digest,uuid);
		if(strncmp(pfdata->uuid,uuid,DIGEST_SIZE*2)!=0)
			return -EINVAL;
	}
	return 0;

}

void * get_message_expand_forward(void * message)
{
	int ret;
	MESSAGE_HEAD * message_head;
	char * expand_type;
	struct  expand_data_forward * expand_forward;
	
//	if(!(message_get_flag(message) & MSG_FLAG_FORWARD))
//		return NULL;
	int i;
	for(i=0;i<MAX_EXPAND_NUM;i++)
	{
		expand_type=message_get_expand_type(message,i);
		if(expand_type==NULL)
		{
			free(expand_type);
			return NULL;
		}
		if(strncmp(expand_type,"FORE",4)!=0)
		{
			free(expand_type);
			continue;
		}
		break;
	}
	if(i==MAX_EXPAND_NUM)
		return NULL;
	ret=message_get_expand(message,&expand_forward,i);
	if(expand_forward==NULL)
	{
		return NULL;	
	}
	return expand_forward;
}	

int get_channel_extern_uuid(void * conn,BYTE * uuid)
{
	struct tcloud_connector * channel_conn=conn;
	if(connector_getstate(channel_conn)!=CONN_CHANNEL)
		return -EINVAL;
	struct connect_proc_info * channel_extern_info = channel_conn->conn_extern_info;

	if(channel_extern_info==NULL)
		return -EINVAL;
	strncpy(uuid,channel_extern_info->uuid,DIGEST_SIZE*2);
	return 0;
}

int set_channel_extern_uuid(void * conn,BYTE * uuid)
{
	struct tcloud_connector * channel_conn=conn;
	if(connector_getstate(channel_conn)!=CONN_CHANNEL)
		return -EINVAL;
	struct connect_proc_info * channel_extern_info = channel_conn->conn_extern_info;

	if(channel_extern_info==NULL)
		return -EINVAL;
	strncpy(channel_extern_info->uuid,uuid,DIGEST_SIZE*2);
	return 0;
}

int get_channel_extern_state(void * conn)
{
	struct tcloud_connector * channel_conn=conn;
	if(connector_getstate(channel_conn)!=CONN_CHANNEL)
		return -EINVAL;
	struct connect_proc_info * channel_extern_info = channel_conn->conn_extern_info;

	if(channel_extern_info==NULL)
		return -EINVAL;
	return  channel_extern_info->channel_state;
}

int set_channel_extern_state(void * conn,int state)
{
	struct tcloud_connector * channel_conn=conn;
	if(connector_getstate(channel_conn)!=CONN_CHANNEL)
		return -EINVAL;
	struct connect_proc_info * channel_extern_info = channel_conn->conn_extern_info;

	if(channel_extern_info==NULL)
		return -EINVAL;
	channel_extern_info->channel_state=state;
	return 0;
}

void * get_record_from_message(void * message_box)
{
	MESSAGE_HEAD * message_head;
	void * record;
	int retval;


	message_head=get_message_head(message_box);
	if(message_head==NULL)
		return NULL;
	retval=alloc_struct(&record,load_record_template(message_head->record_type));
	if(retval<0)
		return NULL;
	retval=message_get_record(message_box,&record,0);
	if(retval<0)
		return NULL;
	return record;
}
