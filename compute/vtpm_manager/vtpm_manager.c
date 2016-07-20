#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "../include/data_type.h"
#include "../include/struct_deal.h"
#include "../include/extern_defno.h"
#include "../include/extern_struct.h"
#include "../include/extern_struct_desc.h"
#include "../include/message_struct.h"
#include "../include/message_struct_desc.h" 
#include "../include/connector.h"
#include "../include/logic_baselib.h"
#include "../include/policy_ui.h"
#include "../include/vm_policy.h"
#include "../include/vm_policy_desc.h"
#include "../include/vmlist.h"
#include "../include/vmlist_desc.h"
#include "../include/vtpm_struct.h"
#include "../include/vtpm_desc.h"
#include "../include/tesi.h"
#include "../include/openstack_trust_lib.h"
#include "vtpm_manager_func.h"

#include "cloud_config.h"

char local_uuid [DIGEST_SIZE*2];
char * proc_name="vtpm_manager";
char * swtpm_path="/home/zsg/tcg/swTPM";
static struct timeval time_val={0,10*1000};

// *vtpm manager's running state : 
//     0        :  init
//     1        :  first time run, should do the init process
//     2        :  init physical tpm success  



int main(int argc, char ** argv)
{
// step 1: make and init buffer database
//
//
	void * struct_template;

	void * record;
	int retval;

	struct tcloud_connector * vtpm_server_conn;
	struct tcloud_connector_hub * hub;
	int ret;
	void * message_box;

	struct tcloud_connector * temp_conn; 

	int i,j;
	pthread_t vtpm_build_thread;

	retval=get_local_uuid(local_uuid);
	printf("this machine's local uuid is %s\n",local_uuid);

	ret=proc_share_data_init(&share_data_desc);
	if(ret<0)
		return -EINVAL;
	proc_share_data_setstate(PROC_LOCAL_INIT);

	TSS_RESULT result;
	BYTE digest[DIGEST_SIZE];


	result=TESI_Local_Reload();
	if ( result != TSS_SUCCESS )
	{
		printf("TESI_Local_Load Err!\n");
		return result;
	}

	proc_share_data_setstate(PROC_LOCAL_TPMOPEN);

	// step 1.0 init the memdb and register lib
	
	openstack_trust_lib_init();
	register_lib("VM_T");
	register_lib("BLBK");
	register_lib("PUBK");

	// step 1.5 load or create the memdb 
	// if lib file exists, we should load this lib
	retval=LoadPolicyFromFile("lib/VM_T.lib","VM_T");
	
	// else, we should init it
	if(retval <=0)
	{
		proc_share_data_setstate(PROC_LOCAL_INITTPM);
		retval=vtpm_info_memdb_init();
		if(retval<0)
			return -EINVAL;
	}

	if(proc_share_data_getstate()!=PROC_LOCAL_LOADLOCALTPMINFO)
	{
		retval=LoadPolicyFromFile("lib/BLBK.lib","BLBK");
		if(retval<0)
			return -EINVAL;

		retval=LoadPolicyFromFile("lib/PUBK.lib","PUBK");
		if(retval<0)
			return -EINVAL;
		proc_share_data_setstate(PROC_LOCAL_LOADLOCALTPMINFO);
	}

	TESI_Local_Fin();
//  step 2: build connector 

	// in this program we will build an unix server and a inet server

	// step 2.1: init the two connector and connector hub
	//
	vtpm_server_conn=get_connector(CONN_SERVER,AF_INET);
	  if((vtpm_server_conn ==NULL) || IS_ERR(vtpm_server_conn))
	{
		printf("get vtpm_server_conn failed!\n");
		exit(-1);
	}

	hub=get_connector_hub();

	ret=vtpm_server_conn->conn_ops->init(vtpm_server_conn,"vtpm_manager_server",vtpm_manager_addr);
	// step 2.2 : add connector to the connector hub
	hub->hub_ops->add_connector(hub,vtpm_server_conn,NULL);

	// step 2.3 let the to connector begin to connect

	ret=vtpm_server_conn->conn_ops->listen(vtpm_server_conn);
	if(ret<0)
	{
		printf("vtpm_manager_server listen error!\n");
		return -EINVAL;
	}

	proc_share_data_setstate(PROC_LOCAL_VTPMSERVERLISTEN);
// step 3 : begin the passive message deal process

	for(;;)
	{

		//  step 3.1 listen the hub to wait message comes
		ret=hub->hub_ops->select(hub,&time_val);
		if(ret<=0)
		{
			continue;
		}
		// step 3.2: deal with different messages

		do{
			// get an activated connector
			temp_conn=hub->hub_ops->getactiveread(hub);
			if(temp_conn==NULL)
				break;

			// if the connector is a server, then this action is a client's connect test
			// we should build a new connector to link it
			if(connector_get_type(temp_conn)==CONN_SERVER)
			{
				struct tcloud_connector * channel_conn;
				void * message;
				BYTE * blob;
				int record_size;

				if(temp_conn==vtpm_server_conn)
				{
					channel_conn=temp_conn->conn_ops->accept(temp_conn);
					if(ret==-1)
					{
						printf("accept error!\n");
						continue;
					}
					printf("accept success!\n");

					if(channel_conn==NULL)
					{
						printf("error: server connector accept error %x!\n",channel_conn);

					}

					// build a server syn message with service name,uuid and proc_name
					message_box=build_server_syn_message("vtpm_manager_server",local_uuid,proc_name);
					if((message_box == NULL) || IS_ERR(message_box))
						continue;
				
					retval=message_send(message_box,channel_conn);
					if(retval<=0)
						continue;
					hub->hub_ops->add_connector(hub,channel_conn,NULL);
					continue;
				}
				else
				{
					printf("error:error connectors!");
					return -EINVAL;
				}
			}
			// if the activated connector is not a server, it should be a channel that get messages to us,
			// we should load the message and begin to deal with it;
			else if(connector_get_type(temp_conn)==CONN_CLIENT)
			{

				return -EINVAL;
			}
			// if the activated connector is not a server, it should be a channel that get messages to us,
			else if(connector_get_type(temp_conn) == CONN_CHANNEL)
			{
				MESSAGE_HEAD * message_head;
				char * sender_uuid;
				char * sender_name;
				char * receiver_uuid;
				char * receiver_name;
				struct expand_data_forward * expand_forward;
		 		struct connect_proc_info * channel_extern_info;
				
				while(read_message_from_conn(&message_box,temp_conn)>0)
				{

					if(get_message_state(message_box)!=MSG_BOX_LOAD)
					{
					 	channel_extern_info=temp_conn->conn_extern_info;
						 if(channel_extern_info==NULL)
						 {
							printf("an invalid local connector!\n");
						 }
						 else
						 {
							printf("error message,disconnect channel to %s!\n",channel_extern_info->proc_name);
						 }
						 hub->hub_ops->del_connector(hub,temp_conn);
						 continue;
					}

					message_head=get_message_head(message_box);
		
					if(strncmp(message_head->record_type,"ACKI",4)==0)
					{
						receive_local_client_ack(message_box,temp_conn);
						continue;
					}

					if(get_message_flag(message_box) & MSG_FLAG_FORWARD)
					{
						expand_forward=get_message_expand_forward(message_box);
						if(expand_forward==NULL)
							continue;

						if(get_message_flag(message_box)&MSG_FLAG_REMOTE)
						{
							if(strncmp(expand_forward->receiver_uuid,local_uuid,DIGEST_SIZE*2)!=0)
								continue;
						}
						if(strcmp(expand_forward->receiver_name,proc_name)!=0)
							continue;
						sender_uuid=dup_str(expand_forward->sender_uuid,DIGEST_SIZE*2);	
						sender_name=dup_str(expand_forward->sender_name,0);
					}
					// or else,we should direct get information from channel's name
					else
					{
						channel_extern_info=temp_conn->conn_extern_info;
						if(channel_extern_info==NULL)
						{
							printf("an invalid local connector!\n");
							continue;
						}
						sender_name=dup_str(channel_extern_info->proc_name,0);
					}
					if(strcmp(channel_extern_info->proc_name,"manager_trust")==0)
					{
						if(strncmp(message_head->record_type,"VM_I",4)==0)
						{	
							if(get_channel_extern_state(temp_conn)>PROC_CHANNEL_READY)
							{
								process_vm_message(message_box,temp_conn);
							}
						}
					}
					else 
					{
						printf("err channe!\n");
					}
					continue;
				 
				}
			}

		}while(1);
	}
	return 0;
}
