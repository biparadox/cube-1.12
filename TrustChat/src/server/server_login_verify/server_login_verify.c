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
//#include <openssl/rsa.h>
//#include <openssl/evp.h>

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
#include "user_info.h"
#include "server_login_verify.h"

int server_login_verify_init(void * sub_proc,void *para)
{

	return 0;
}

int server_login_verify_start(void *sub_proc,void *para)
{
	int ret;
	void * recv_msg;
	int i;
	const char * type;

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
		if(strncmp(type,"LOGI",4)==0)
			proc_server_login_verify(sub_proc,recv_msg);
	}

}

int proc_server_login_verify(void * sub_proc,void *message)
{
	char * type;
	int i;
	int ret;

	struct expand_flow_trace * flow_trace;
	message_get_expand(message,&flow_trace,0);
	printf("*******|%s|*******\n",flow_trace->trace_record);

	message_get_define_expand(message,&flow_trace,"FTRE");
	printf("*******|%s|*******\n",flow_trace->trace_record);

	printf("begin proc user-addr table build! \n");
	struct message_box * msg_box=message;
	type=message_get_recordtype(message);
	struct user_addr_list *user_db;
	struct message_box * new_msg;
        struct login_info *login_data;
        struct user_info_list *lib_data;
        struct connect_return *return_data; 
// 	void * record;
	new_msg=message_create("RETC",message);
	return_data=malloc(sizeof(struct connect_return));
	user_db=malloc(sizeof(struct user_addr_list));
	memset(return_data,0,sizeof(struct connect_return));
	i=0;
	ret=message_get_record(message,&login_data,0);
	printf("***************--%s--*****************\n",login_data->user);
	
	memcpy(user_db->user,login_data->user,DIGEST_SIZE);
	memcpy(user_db->addr,flow_trace->trace_record,DIGEST_SIZE*2);
	user_db->state=USER_CONN_CONNECTED;
	
	AddPolicy(user_db,"U2AL");
	
//	ExportPolicy("U2AL");
	//struct user_db only_one;
	//only_one->user = login_data->user;
	//only_one->user_uuid = flow_trace->trace_record;
	
//        if(ret<0)
//           return ret;
//        ret=FindPolicy(login_data->user,"UL_I",&lib_data);
//	if(ret<0)
//	{
//	 return_data->ret_data=dup_str("login verify system error!",0);
//	}
//        else if(lib_data==NULL){
//         return_data->ret_data=dup_str("no such user!",0);
//	}
//        else if(strncmp(lib_data->passwd,login_data->passwd,DIGEST_SIZE*2))
//        {
//         return_data->ret_data=dup_str("error passwd!",0);
//	}
//	else
//	{
//
//          return_data->ret_data=dup_str("login succeed!",0);
 //         return_data->retval=1;
//	}
/*	while(record!=NULL)
	{
		message_add_record(new_msg,record);
		ret=message_get_record(message,&record,i++);
		if(ret<0)
			return ret;
	}*/
//        return_data->ret_data_size=strlen(return_data->ret_data);
//        message_add_record(new_msg,return_data);
//	sec_subject_sendmsg(sub_proc,new_msg);
//	return ret;
}
