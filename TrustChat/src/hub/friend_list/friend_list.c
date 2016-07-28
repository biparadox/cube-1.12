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

#include "friend_list.h"
#include "user_info.h"

int friend_list_init(void * sub_proc,void * para)
{
        int ret;
        // add youself's plugin init func here
        return 0;
}

int friend_list_start(void * sub_proc,void * para)
{
        int ret;
        void * recv_msg;
        int i;
        const char * type;

	void * new_msg;
	struct user_info_list * user_info;
	struct login_info * friend;

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
		if(strncmp(type,"RETC",4)==0)
                	friend_list_message(sub_proc,recv_msg);
        }

        return 0;
};

int friend_list_message(void * sub_proc,void * message)
{
        int i;
        int ret;
	void *  new_msg;
	struct user_info_list * user_info;
	struct login_info * friend;
        struct connect_return *return_data;

	ret=message_get_record(message,&return_data,0);
	if(ret<0)
		return -EINVAL;
	if(return_data==NULL)
		return 0;

        sec_subject_sendmsg(sub_proc,message);
	if(return_data->retval!=1)
	{
        	printf("user login failed! \n");
		return 0;
	}	
	
        printf("begin to send friend_list_message  \n");
	

	ret=GetFirstPolicy(&user_info,"UL_I");
	if(ret<0)
		return ret;
        new_msg=message_create("LOGI",message);
	while(user_info!=NULL)
	{
		if(user_info->state==USER_GENERAL)
		{
        		friend=malloc(sizeof(struct login_info));
			if(friend==NULL)
				return -ENOMEM;
      		  	memset(friend,0,sizeof(struct login_info));
			strncpy(friend->user,user_info->name,DIGEST_SIZE);
        		message_add_record(new_msg,friend);
		}
		ret=GetNextPolicy(&user_info,"UL_I");
		if(ret<0)
			return ret;
	}
	usleep(50*1000);
        sec_subject_sendmsg(sub_proc,new_msg);

        return 0;
}
