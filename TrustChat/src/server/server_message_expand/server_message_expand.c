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
#include "../include/main_proc_init.h"
#include "../include/valuename.h"
#include "../include/expand_define.h"

#include "session_msg.h"
#include "server_message_expand.h"
#include "user_info.h"

int server_message_expand_init(void * sub_proc,void * para)
{
	int ret;
	// add youself's plugin init func here
	return 0;
}

int server_message_expand_start(void * sub_proc,void * para)
{
	int ret;
	void * recv_msg;
	int i;
	const char * type;

	usleep(500*1000);

	for(i=0;i<3000*1000;i++)
	{
		usleep(time_val.tv_usec);
		ret=sec_subject_recvmsg(sub_proc,&recv_msg);
		if(ret<0)
			continue;
		if(recv_msg==NULL)
			continue;
		type=message_get_recordtype(recv_msg);
		if(type==NULL)
		{
			printf("message format error!\n");
			continue;
		}
		if(!find_record_type(type))
		{
			printf("message format is not registered!\n");
			continue;
		}
		if(strncmp(type,"MSGD",4)==0)
			transport_message1(sub_proc,recv_msg);
	}

	return 0;
};

int transport_message1(void * sub_proc,void * message)
{
	const char * type;
	int i;
	int ret;
	
	//struct expand_time_stamp * time_stamp;
	//char * timestr;
	//time_stamp = malloc(sizeof(struct expand_time_stamp));
	printf("begin message addr finding! \n");
	struct message_box * msg_box=message;

	struct message_box * new_msg;
	struct session_msg * echo_msg;
	time_t tm;


	if(message_get_flag(message)&MSG_FLAG_CRYPT)
	{
               	struct user_name_expand  *user_name;
               	struct expand_extra_info  *eei;
               	eei=malloc(sizeof(struct expand_extra_info));
   		struct user_addr_list *first_msg;
               	ret=message_get_define_expand(message,&user_name,"USNE");
               	if(ret<0)
 	   		return ret;
		if(user_name==NULL)
		{
			printf("private message no receiver!\n");
			return -EINVAL;
		}
               	ret=FindPolicy(user_name->name,"U2AL",&first_msg);
		if(ret<0)
                       	return -EINVAL;
               	if(first_msg==NULL)
               	{
               		printf("find addr failed!\n");
                       	return -EINVAL;
		}
               	if(eei==NULL)
                       	return -ENOMEM;
               	memset(eei->uuid,0,DIGEST_SIZE*2);
               	memcpy(eei->uuid,first_msg->addr,DIGEST_SIZE*2);
               	eei->data_size=sizeof(struct expand_extra_info );
               	memcpy(eei->tag,"EEIE",4);
               	message_add_expand(message,eei);
		sec_subject_sendmsg(sub_proc,message);
	}
	else
	{

		ret=message_get_record(message,&echo_msg,0);
		if(echo_msg==NULL)
			return 0;
	
	
        	if(echo_msg->flag==MSG_PRIVATE){
                	struct user_name_expand  *user_name;
                	struct expand_extra_info  *eei;
                	eei=malloc(sizeof(struct expand_extra_info));
   			struct user_addr_list *first_msg;
                	ret=message_get_define_expand(message,&user_name,"USNE");
                	if(ret<0)
 		   		return ret;
			if(user_name==NULL)
			{
				printf("private message no receiver!\n");
				return -EINVAL;
			}
                	ret=FindPolicy(user_name->name,"U2AL",&first_msg);
			if(ret<0)
                        	return -EINVAL;
                	if(first_msg==NULL)
                	{
                		printf("find addr failed!\n");
                        	return -EINVAL;
			}
                	if(eei==NULL)
                        	return -ENOMEM;
                	memset(eei->uuid,0,DIGEST_SIZE*2);
               		memcpy(eei->uuid,first_msg->addr,DIGEST_SIZE*2);
                	eei->data_size=sizeof(struct expand_extra_info );
                	memcpy(eei->tag,"EEIE",4);
                	message_add_expand(message,eei);
			sec_subject_sendmsg(sub_proc,message);
		}
               
		else if(echo_msg->flag==MSG_GENERAL){
                	struct expand_extra_info  *eei;
			void * search_from_db;
			struct user_addr_list * first_msg;
			ret=GetFirstPolicy(&first_msg,"U2AL");
	        	if(ret<0)
        	        	return -EINVAL;
			while(first_msg!=NULL)
			{
				
				new_msg=message_clone(message);

               	 		eei =malloc(sizeof(struct expand_extra_info));
                		if(eei==NULL)
                        		return -ENOMEM;
                		memset(eei->uuid,0,DIGEST_SIZE*2);
                		memcpy(eei->uuid,first_msg->addr,DIGEST_SIZE*2);
                		eei->data_size=sizeof(struct expand_extra_info );
                		memcpy(eei->tag,"EEIE",4);
                		message_add_expand(new_msg,eei);
				sec_subject_sendmsg(sub_proc,new_msg);
				ret=GetNextPolicy(&first_msg,"U2AL");
	        		if(ret<0)
        	        		return -EINVAL;
			}
        	}

        }
//	message_add_record(new_msg,echo_msg);
	//timestr=ctime_r(&tm,time_stamp->time);
	//if (timestr<=0)
	//	return -EINVAL;

	//message_add_expand(new_msg,time_stamp);
	return ret;
}
