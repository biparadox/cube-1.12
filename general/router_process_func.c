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

int proc_router_recv_msg(void * message,char * local_uuid,char * proc_name)
{
	void * sec_sub;
	int ret;
	MESSAGE_HEAD * msg_head;

	if(message_get_state(message) & MSG_FLOW_LOCAL)
		return 0;

	if(message_get_state(message) & MSG_FLOW_DELIVER)
	{
		return 0;
	}

	if(message_get_state(message) & MSG_FLOW_RESPONSE)
	{
		
		ret=router_check_sitestack(message,"FTRE");
		if(ret<0)
			return ret;
		// if response stack finished, set the state to FINISH 
		if(ret==0)
			message_set_state(message, MSG_FLOW_FINISH);
	}
	if(message_get_state(message) & MSG_FLOW_ASPECT)
	{
		
		ret=router_check_sitestack(message,"APRE");
		if(ret<0)
			return ret;
		if(ret==0)
		{
			// if aspect stack finished, remove the aspect flag from state 
			int state=message_get_state(message) &(~MSG_FLOW_ASPECT);
			message_set_state(message, state);
		}
	}
	return 0;
}

int proc_router_send_msg(void * message,char * local_uuid,char * proc_name)
{
	void * sec_sub;
	int ret;
	MESSAGE_HEAD * msg_head;
	BYTE conn_uuid[DIGEST_SIZE*2];

	if(message_get_state(message) & MSG_FLOW_LOCAL)
	{
		msg_head=get_message_head(message);
		if(msg_head==NULL)
		{
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
		return -EINVAL;
	}
	return 0;
}

int proc_router_init(void * sub_proc,void * para)
{
    int ret;
    // main proc: read router config	
    const char * config_filename= "./router_policy.cfg";

    router_policy_init();
    ret=router_read_cfg(config_filename);	
    if(ret<=0)
    {
	    printf("read router policy error %d!\n",ret);
//	    return ret;
    }

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
	char *isostr="\n************************************************************\n";
	BYTE conn_uuid[DIGEST_SIZE*2];
	
	ret=proc_share_data_getvalue("uuid",local_uuid);
	ret=proc_share_data_getvalue("proc_name",proc_name);

	char audit_text[4096];
        const char * audit_filename= "./message.log";
    	int fd =open(audit_filename,O_CREAT|O_RDWR|O_TRUNC);
        close(fd);


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
		void * aspect_policy;

		// throughout all the sub_proc
		ret=get_first_sec_subject(&sub_proc);
		msg_policy=NULL;
		while(sub_proc!=NULL)
		{
			void * message;
			void * router_rule;
			int state;
			int flow;
			// receiver the message
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
			
			state=message_get_state(message);
			flow=message_get_flow(message);
			MESSAGE_HEAD * msg_head=get_message_head(message);


			if(flow & MSG_FLOW_ASPECT_LOCAL)  // local aspect message return
			{

				flow = flow & (~MSG_FLOW_LOCAL);
				message_set_flow(message, flow);
				if(flow & MSG_FLOW_ASPECT)  //  message should return the remote aspect point
				{
					ret=router_check_sitestack(message,"APRE");
					if(ret<0)
					{
						message_free(message);
						continue;
					}
					else if(ret==0)
					{
						// if aspect stack finished, remove the aspect flag from state 
						flow = flow &(~MSG_FLOW_ASPECT);
						message_set_flow(message, flow);
					}
					else
					{
						// if aspect stack still has value, pop the value, and let information return the node value pointed 
						ret=router_pop_site(message,msg_head->receiver_uuid,"APRE");
						if(ret<0)
						{
							message_free(message);
							continue;
						}
					}
				}
			}

			else 
			{
				if( ! (flow & MSG_FLOW_ASPECT))  //  if router receive an aspect message, it should find aspect policy immediately
								 //  or router should check if message's flow has  response flag and it is in the 
								 //  deliver state or response state 
				{
					if(state & MSG_FLOW_RESPONSE) 
					{
						ret=router_check_sitestack(message,"FTRE");
						if(ret<0)
						{
							message_free(message);
							continue;
						}
						else if(ret==0)
						{
							// if FTRE stack is empty, set the state to MSG_FLOW_FINISH 
							message_set_state(message, MSG_FLOW_FINISH);
						}
						else
						{
							ret=router_pop_site(message,msg_head->receiver_uuid,"FTRE");
							if(ret<0)
							{
								message_free(message);
								continue;
							}

						}

					}
					else if((flow & MSG_FLOW_RESPONSE)
							&& (state == MSG_FLOW_LOCAL))
					{
						// if FTRE stack still has value, pop the value, and let information return the node value pointed 
						ret=router_pop_site(message,msg_head->receiver_uuid,"FTRE");
						if(ret<0)
						{
							message_free(message);
							continue;
						}
						message_set_state(message,MSG_FLOW_RESPONSE);
					}
					if( (state & MSG_FLOW_INIT)
						|| (state &MSG_FLOW_DELIVER)
						|| (state & MSG_FLOW_FINISH)) 	// message is not the response state, 
										// we should find the match policy and set the main router  
					{
						ret=router_find_match_policy(message,&msg_policy,sec_subject_getname(sub_proc));
						if(ret<0)
						{
							message_free(message);
							continue;
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
							printf("set main flow failed!\n");
							continue;
						}

					}
					else
					{
						continue;
					}

				}

			}

			// find the sender's aspect policy

			ret=router_find_aspect_policy(message,&aspect_policy,sec_subject_getname(sub_proc));
			if(ret<0)
			{
				message_free(message);
				continue;
			}
			if(aspect_policy!=NULL)
			{
				ret=router_set_aspect_flow(message,aspect_policy);// set the aspect flow policy
				if(ret<0)
				{
					message_free(message);
					continue;
				}
				if(!(message_get_flow(message) & MSG_FLOW_ASPECT_LOCAL))
				{
					comp_proc_uuid(local_uuid,proc_name,conn_uuid);
					router_push_site(message,conn_uuid,"APRE");
				}
				
			}
			else  if(msg_policy!=NULL)
			{
				router_rule=router_get_first_duprule(msg_policy);
				while(router_rule!=NULL)
				{
					void * dup_msg;
					ret=router_set_dup_flow(message,router_rule,&dup_msg);
					if(ret<0)
						break;
					if(dup_msg!=NULL)
					{
						ret=message_2_json(dup_msg,audit_text);	
						audit_text[ret]='\n';			
    						fd=open(audit_filename,O_WRONLY|O_CREAT|O_APPEND);
    						if(fd<0)
	  						return -ENOENT;
						write(fd,audit_text,ret+1);
						close(fd);
						proc_router_send_msg(dup_msg,local_uuid,proc_name);
					}
					router_rule=router_get_next_duprule(msg_policy);
				}

				flow=message_get_flow(message);
				state=message_get_state(message);

				if( (flow & MSG_FLOW_RESPONSE)
					&&( state &MSG_FLOW_DELIVER))
				{
					comp_proc_uuid(local_uuid,proc_name,conn_uuid);
					router_push_site(message,conn_uuid,"FTRE");
				}
			}
			ret=message_2_json(message,audit_text);	

			audit_text[ret]='\n';			
    			fd=open(audit_filename,O_WRONLY|O_CREAT|O_APPEND);
    			if(fd<0)
	  			return -ENOENT;
			write(fd,audit_text,ret+1);
			write(fd,isostr,strlen(isostr));
			close(fd);

			ret=proc_router_send_msg(message,local_uuid,proc_name);
			if(ret<0)
			{
				printf("router send message to main flow failed!\n");
			}
		
			continue;
		}
	
	}
	return 0;
}
