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
#include "../include/logic_baselib.h"
#include "../include/sec_entity.h"
#include "../include/valuename.h"
#include "../include/main_proc_init.h"
#include "../include/expand_define.h"

#include "../cloud_config.h"
#include "router_process_func.h"

int proc_router_init(void * sub_proc,void * para)
{
    int ret;
    // main proc: read router config	
    const char * config_filename= "./main_proc_policy.cfg";

    router_policy_init();
    ret=router_read_cfg(config_filename);	
    if(ret<=0)
    {
	    printf("read router policy error %d!\n",ret);
//	    return ret;
    }

    ret=sec_subject_create_statelist(sub_proc, router_process_state_name);
    if(ret<0)
	return ret;	
    ret=sec_subject_register_statelist(sub_proc,router_state_list);
    if(ret<0)
	return ret;	

    ret=sec_subject_create_funclist(sub_proc, router_process_func_name);
    if(ret<0)
	return ret;	
    ret=sec_subject_register_funclist(sub_proc, router_func_list);
    if(ret<0)
	return ret;	
//	register_record_type("CONE",expand_data_router_desc,NULL);


    void * context;
    ret=sec_subject_getcontext(sub_proc,&context);
    if(ret<0)
	return ret;
    return 0;
}


int proc_router_start(void * sub_proc,void * para)
{
	int ret;
	int retval;
	void * message_box;
	MESSAGE_HEAD * message_head;
	void * context;
	int i,j;
	char local_uuid[DIGEST_SIZE*2+1];
	char proc_name[DIGEST_SIZE*2+1];
	char receiver_uuid[DIGEST_SIZE*2+1];
	
	ret=proc_share_data_getvalue("uuid",local_uuid);
	ret=proc_share_data_getvalue("proc_name",proc_name);


//	struct timeval time_val={0,10*1000};
	struct timeval router_val;
	router_val.tv_usec=time_val.tv_usec;

	// message routing loop
	for(i=0;i<5000*1000;i++)
	{
		usleep(router_val.tv_usec);
		void * sub_proc;
		char * receiver_proc;
		char * sender_proc;
		void * msg_policy;
		ret=get_first_sec_subject(&sub_proc);
		msg_policy=NULL;
		while(sub_proc!=NULL)
		{
			void * message;
			// receiver message
			ret=recv_sec_subject_msg(sub_proc,&message);
			if(ret<0)
			{
				get_next_sec_subject(&sub_proc);
				continue;
			}
			else if((message==NULL) ||IS_ERR(message))
			{
				get_next_sec_subject(&sub_proc);
				continue;	
			}
			printf("router get proc %s's message!\n",sec_subject_getname(sub_proc)); 
			ret=router_find_match_policy(message,&msg_policy);
			if(ret<0)
			{
				message_free(message);
				return -EINVAL;
			}
			if(msg_policy==NULL)
			{
				message_free(message);
				continue;
			}

			ret=router_set_main_flow(message,msg_policy);
			if(ret<0)
			{
				message_free(message);
				return -EINVAL;
			}

			if(message_get_state(message) & MSG_FLOW_LOCAL)
			{
				void * sec_sub;
				MESSAGE_HEAD * msg_head=get_message_head(message);
				if(msg_head==NULL)
				{
					message_free(message);
					return  -EINVAL;
				}
				ret=find_sec_subject(msg_head->receiver_uuid,&sec_sub);	
				if(sec_sub!=NULL)
				{
					if(sec_subject_getprocstate(sec_sub)<SEC_PROC_START)
					{	
						printf("start process %s!\n",sec_subject_getname(sec_sub));
    						ret=sec_subject_start(sec_sub,NULL);
					}
					send_sec_subject_msg(sec_sub,message);
					printf("send message to local process %s!\n",msg_head->receiver_uuid);
				}
			}
			else if(message_get_state(message) & MSG_FLOW_DELIVER)
			{
				void * sec_sub;
				if(message_get_flow(message) & MSG_FLOW_RESPONSE)
					router_push_site(message,local_uuid);

				ret=find_sec_subject("connector_proc",&sec_sub);	
				if(sec_sub==NULL)
				{
					printf("can't find conn process!\n");
					return -EINVAL;
				}
				send_sec_subject_msg(sec_sub,message);
				printf("send message to conn process!\n");
				
			}
			else if(message_get_state(message) & MSG_FLOW_RESPONSE)
			{
				void * sec_sub;
				MESSAGE_HEAD * msg_head=get_message_head(message);
				if(strncmp(msg_head->receiver_uuid,local_uuid,DIGEST_SIZE*2)==0)
				{
					printf("no one accept the %s message from %s!\n",msg_head->record_type,msg_head->sender_uuid); 
					message_free(message);
					continue;
				}

				ret=router_pop_site(message,msg_head->receiver_uuid);
				if(ret<0)
				{
					printf("response %s message routing can't find the end!\n",msg_head->record_type); 
					message_free(message);
					continue;

				}

				ret=find_sec_subject("connector_proc",&sec_sub);	
				if(sec_sub==NULL)
				{
					printf("can't find conn process!\n");
					return -EINVAL;
				}
				send_sec_subject_msg(sec_sub,message);
				printf("send message to conn process!\n");
			}
			else if(message_get_state(message) & MSG_FLOW_ASPECT)
			{
				void * sec_sub;

				ret=find_sec_subject("connector_proc",&sec_sub);	
				if(sec_sub==NULL)
				{
					printf("can't find conn process!\n");
					return -EINVAL;
				}
				send_sec_subject_msg(sec_sub,message);
				printf("send message to conn process!\n");
			}
			else
			{
				message_free(message);
			}

			break;
		}
		if(sub_proc==NULL)
			continue;
	
	}
	return 0;
};
