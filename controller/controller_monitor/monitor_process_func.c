#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <mysql/mysql.h>
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

#include "cloud_config.h"
#include "monitor_process_func.h"
#include "local_func.h"

int monitor_process_init(void * sub_proc,void * para)
{
	int ret;
	char local_uuid[DIGEST_SIZE*2];

	return 0;
}

int monitor_process_start(void * sub_proc,void * para)
{
	int ret;
	int retval;
	void * message_box;
	void * context;
	void * recv_msg;
	void * send_msg;
	struct tcloud_connector * temp_conn;
	int i;

	char local_uuid[DIGEST_SIZE*2+1];
	char proc_name[DIGEST_SIZE*2+1];
	
	ret=proc_share_data_getvalue("uuid",local_uuid);
	if(ret<0)
		return ret;
	ret=proc_share_data_getvalue("proc_name",proc_name);

	printf("begin monitor process!\n");
	if(ret<0)
		return ret;

	struct vm_info * vm;
	
	message_box=message_create("VM_I",NULL);
	if(message_box==NULL)
		return -EINVAL;
	if(IS_ERR(message_box))
		return -EINVAL;
	vm=GetFirstPolicy("VM_I");
	while( vm != NULL)
	{
		message_add_record(message_box,vm);
		vm=GetNextPolicy("VM_I");
	}
	// send init message
	sec_subject_sendmsg(sub_proc,message_box);
	
	usleep(time_val.tv_usec);


	struct image_info * image;
	
	message_box=message_create("IMGI",NULL);
	if(message_box==NULL)
		return -EINVAL;
	if(IS_ERR(message_box))
		return -EINVAL;
	image=GetFirstPolicy("IMGI");
	while( image != NULL)
	{
		message_add_record(message_box,image);
		image=GetNextPolicy("IMGI");
	}
	// send init message
	sec_subject_sendmsg(sub_proc,message_box);
	
	usleep(time_val.tv_usec);
	struct platform_info * platform;
	
	message_box=message_create("PLAI",NULL);
	if(message_box==NULL)
		return -EINVAL;
	if(IS_ERR(message_box))
		return -EINVAL;
	platform=GetFirstPolicy("PLAI");
	while( platform != NULL)
	{
		message_add_record(message_box,platform);
		platform=GetNextPolicy("PLAI");
	}
	// send init message
	sec_subject_sendmsg(sub_proc,message_box);
	

	usleep(time_val.tv_usec);
	// begin monitor
	struct vm_policy * vm_policy;
	
	for(i=0;i<3000*1000;i++)
	{
		usleep(time_val.tv_usec);
		ret=sec_subject_recvmsg(sub_proc,&recv_msg);
		if(ret<0)
			continue;
		if(recv_msg==NULL)
			continue;
		MESSAGE_HEAD * msg_head;
		msg_head=get_message_head(recv_msg);
		if(msg_head==NULL)
			continue;
		if(strncmp(msg_head->record_type,"REQC",4)==0)
		{

			struct request_cmd * cmd;
			ret=message_get_record(recv_msg,&cmd,0);
			if(strncmp(cmd->tag,"IMGP",4)==0)
			{
				proc_send_imagepolicy(sub_proc,recv_msg);
			}
			else
				continue;
				
		}
	}
	return 0;
}

int process_monitor_image(void * sub_proc,void * para)
{
	struct image_info  * image;
	struct vm_policy  * image_policy;
	void * message;
	MESSAGE_HEAD * message_head;
	int record_size;
	BYTE * blob;
	int bloboffset;
	int record_num;
	int ret;
	char local_uuid[DIGEST_SIZE*2];

	// send init message to 
	image=GetFirstPolicy("IMGI");
	while( image!= NULL)
	{
		message=message_create("IMGI",NULL);
		if(message==NULL)
			return -EINVAL;
		if(IS_ERR(message))
			return -EINVAL;
		message_add_record(message,image);
		ret=sec_subject_sendmsg(sub_proc,message);
		if(ret<=0)
		{
			printf("send image message error!");
		}
		else
		{
			printf("send image %s 's message !\n",image->uuid);
		}
		image_policy=FindPolicy(image->uuid,"IMGP");
		if(image_policy==NULL)
		{
			printf("image %s has no policy!\n",image->uuid);
		}
		else
		{
			message=message_create("IMGP",NULL);
			if(message==NULL)
				return -EINVAL;
			if(IS_ERR(message))
				return -EINVAL;
			message_add_record(message,image_policy);
			ret=sec_subject_sendmsg(sub_proc,message);
			if(ret<=0)
			{
				printf("send image policy message error!\n");
			}
		}
    		image=GetNextPolicy("IMGI");
	}

	monitor_image_from_dbres(sub_proc);
	return 0;
}

int process_monitor_platform(void * sub_proc,void * para)
{
	return 0;
}

int monitor_vm_from_dbres(void * sub_proc)
{
	MYSQL  my_connection;
        MYSQL_RES * res_ptr;
        MYSQL_RES * res_ptr1;
        MYSQL_ROW sqlrow;
	void * message;
	BYTE * blob;
	char sql[256];
	char uid[256];
	char temp[256];
	char key[256];
        int res;
	int i,j;
	int ret;
	struct vm_info * vm;
	int offset;
	int record_size;
	int bloboffset;
	int curid=0;
	char local_uuid[DIGEST_SIZE*2];
	vm=malloc(sizeof(struct vm_info));
	if(vm==NULL)
                return -EINVAL;
        memset(vm,0,sizeof(struct vm_info));
	
	mysql_init(&my_connection);
	
	if(!mysql_real_connect(&my_connection,"172.21.5.8","root","openstack",NULL,3306,NULL,0))
	{
                printf("CONNECTION FAILED\n");
	}
	if (mysql_select_db(&my_connection, "nova"))
        {
                printf("CONNECTION database FAILED\n");
        }
	strcpy(sql,"select max(id) from instances");
        res=mysql_query(&my_connection,sql);

        if(res)
        {
                printf("SELECT error");
                return 0;
        }

        res_ptr=mysql_store_result(&my_connection);
	j=mysql_num_fields(res_ptr);
        if(j==1)
        {
                sqlrow=mysql_fetch_row(res_ptr);
                curid=atoi(sqlrow[0]);
        }
	while(1)
        {
                usleep(10000*1000);
                sprintf(sql,"select uuid from instances where id>%d and deleted_at is NULL",curid);
                res=mysql_query(&my_connection,sql);
                res_ptr1=mysql_store_result(&my_connection);
                j=mysql_num_rows(res_ptr1);
       		 if(j==0)
                {
                        printf("SELECT none VM\n");
                        continue;
                }
		while((sqlrow=mysql_fetch_row(res_ptr1)))
                {
			printf("select changes from db of vm");
                        sleep(10);
                        ret=get_vm_from_dbres(&vm,sqlrow,&my_connection);
                        if(ret<0)
                                  return -EINVAL;
			/*
                        strcpy(uid,sqlrow[0]);
                        sprintf(sql,"select p1.uuid,p1.memory_mb,p1.vcpus,p1.root_device_name,p2.hypervisor_type ,p1.image_ref"
				", p1.id FROM instances AS p1,compute_nodes as p2 WHERE p1.uuid='%s' and "
				"p1.host=p2.hypervisor_hostname order by id",uid);
                        res=mysql_query(&my_connection,sql); //此处为选择语句，根据相关数据字段添加
                        if(res)
		        {
                        	printf("SELECT error2");
                                return 0;
                        }
			else
                        {
                                res_ptr=mysql_store_result(&my_connection);
                                sqlrow=mysql_fetch_row(res_ptr);
                                if(j=mysql_num_fields(res_ptr)==7)
                                {
                         		strcpy(vm->uuid,sqlrow[0]);
                        		vm->memory=atol(sqlrow[1])*1024;
                                        vm->vcpu=atoi(sqlrow[2]);
                                        int i;
                                        strcpy(temp,sqlrow[3]);
                                        vm->diskinfo.dev=malloc(strlen(temp)-4);
                                        if(vm->diskinfo.dev==NULL)
                                        	return -ENOMEM;
                                        strcpy(vm->diskinfo.dev,&(temp[5]));
                                        strcpy(temp,sqlrow[4]);
                                        int l=strlen(temp);
                                       	for(i=0;i<l;i+=1)
                                	{
                                       		temp[i]=tolower(temp[i]);
                                       	}
                                       	 vm->diskinfo.name=malloc(strlen(temp)+1);
                                       	 if(vm->diskinfo.name==NULL)
                                       		 return -ENOMEM;
                                        strcpy(vm->diskinfo.name,temp);
                                        strcpy(key,sqlrow[5]);
                                        curid=atoi(sqlrow[6]);
                            	}
                               	mysql_free_result(res_ptr);
                	}	

//        			if (mysql_select_db(&my_connection, "quantum"))
  //      			{
    //           				 printf("CONNECTION database FAILED\n");
      //  			}	

//        			sprintf(sql,"select mac_address from ports where device_id='%s' ",vm->uuid);
  //     				 res=mysql_query(&my_connection,sql);
//				if(res)
  //      			{
    //            			printf("SELECT error: %s\n,",mysql_error(&my_connection));
//  			}	
//        			else
  //      			{
    //            			res_ptr=mysql_store_result(&my_connection);
      //          			sqlrow=mysql_fetch_row(res_ptr);
        //        			vm->network.macadd=malloc(strlen(sqlrow[0])+1);
//                        	if(vm->network.macadd==NULL)
  //                              	return -ENOMEM;
 //               		strcpy(vm->network.macadd,sqlrow[0]);
   //     			}
       			mysql_free_result(res_ptr);
       			if (mysql_select_db(&my_connection, "glance"))
       			{
               			printf("CONNECTION database FAILED\n");
       			}
       			sprintf(sql,"select disk_format from images where id ='%s' ",key);
       			res=mysql_query(&my_connection,sql);

       			if(res)
       			{
               			printf("SELECT error: %s\n,",mysql_error(&my_connection));
       			}
			else
       			{
               			res_ptr=mysql_store_result(&my_connection);
               			sqlrow=mysql_fetch_row(res_ptr);
            			vm->diskinfo.type=malloc(strlen(sqlrow[0])+1);
                        	if(vm->diskinfo.type==NULL)
                               		 return -ENOMEM;
                		strcpy(vm->diskinfo.type,sqlrow[0]);
        		}
                	vm->os.type=malloc(strlen("hvm")+1);
        		if(vm->os.type==NULL)
               			return -ENOMEM;
        		strcpy(vm->os.type,"hvm");
       			 vm->os.bootdev=malloc(strlen("hd")+1);
        		if(vm->os.bootdev==NULL)
               			return -ENOMEM;
        		strcpy(vm->os.bootdev,"hd");
        		vm->diskinfo.cache=malloc(strlen("none")+1);
        		if(vm->diskinfo.cache==NULL)
              			 return -ENOMEM;
        		strcpy(vm->diskinfo.cache,"none");
        		vm->network.interfacetype=malloc(strlen("bridge")+1);
        		if(vm->network.interfacetype==NULL)
               			return -ENOMEM;
       			 strcpy(vm->network.interfacetype,"bridge");
       			 vm->network.model=malloc(strlen("virtio")+1);
			if(vm->network.model==NULL)
              			 return -ENOMEM;
       			 strcpy(vm->network.model,"virtio");
       			 vm->network.bridge=malloc(strlen("qbrc5783fa4-8e")+1);
        		if(vm->network.bridge==NULL)
               			return -ENOMEM;
        		strcpy(vm->network.bridge,"qbrc5783fa4-8e");
       			 vm->network.dev=malloc(strlen("tapc5783fa4-8e")+1);
        		if(vm->network.dev==NULL)
              			 return -ENOMEM;
       			 strcpy(vm->network.dev,"tapc5783fa4-8e");
       			 vm->diskinfo.bus=malloc(strlen("virtio")+1);
       			 if(vm->diskinfo.bus==NULL)
              			 return -ENOMEM;
       			 strcpy(vm->diskinfo.bus,"virtio");
       			 sprintf(temp,"/var/lib/nova/instances/%s/console.log",vm->uuid);
       			 vm->filepath=malloc(strlen(temp)+1);
       			 if(vm->filepath==NULL)
              			 return -ENOMEM;
       			 strcpy(vm->filepath,temp);
       			 sprintf(temp,"/var/lib/nova/instances/%s/disk",vm->uuid);
       			 vm->diskinfo.sourcefile=malloc(strlen(temp)+1);
       			 if(vm->diskinfo.sourcefile==NULL)
              			 return -ENOMEM;
			strcpy(vm->diskinfo.sourcefile,temp);
			*/
			message=message_create("VM_I",NULL);
			if(message==NULL)
				return -EINVAL;
			if(IS_ERR(message))
				return -EINVAL;
			message_add_record(message,vm);
			ret=sec_subject_sendmsg(sub_proc,message);
			/*
			record_size=output_message_blob(message,&blob);
			if(record_size<=0)
				return -EINVAL;
			ret=policy_server_conn->conn_ops->write(policy_server_conn,blob,record_size);
			if(ret<=0)
			{
				printf("send vm message error!");
			}
			else
			{
				printf("send vm %s 's message to policy server!\n",vm->uuid);
			}
			message_free(message);
			*/
			free(message);
				
		}
		j=0;
		mysql_select_db(&my_connection, "nova");
		mysql_free_result(res_ptr1);
                continue;
	}
	mysql_close(&my_connection);
	return 1;
}

int monitor_image_from_dbres(void * sub_proc)

{
	struct image_info  * image;
        void * message;
	int retval;
        int record_size;
        BYTE * blob;
        int record_num;
        int ret;
	        MYSQL  my_connection;
	char local_uuid[DIGEST_SIZE*2];
        MYSQL_RES * res_ptr;
        MYSQL_RES * res_ptr1;
        MYSQL_ROW sqlrow;
        int i,j;
	int reval;
        int bloboffset;
        int curid=0;
	 mysql_init(&my_connection);
   	 if(!mysql_real_connect(&my_connection,"172.21.5.8","root","openstack",NULL,3306,NULL,0))
    	{
                printf("CONNECTION FAILED\n");
    	}	
	       char key[256];
        char temp[256];
        char sql[256];
        int res;
	char uid[256];
	if (mysql_select_db(&my_connection, "glance"))
        {
                printf("CONNECTION database FAILED\n");
        }
	strcpy(sql,"select max(id) from image_locations");
	res=mysql_query(&my_connection,sql);

        if(res)
        {
                printf("SELECT error");
                return 0;
        }

        res_ptr=mysql_store_result(&my_connection);
        j=mysql_num_fields(res_ptr);
        if(j==1)
        {
                sqlrow=mysql_fetch_row(res_ptr);
                curid=atoi(sqlrow[0]);
        }
        mysql_free_result(res_ptr);

	 while(1)
        {
                // scan new image
                sleep(10);
                sprintf(sql,"select image_id,id from image_locations where id>%d and deleted_at is NULL order by id",curid);
                res=mysql_query(&my_connection,sql);
                res_ptr1=mysql_store_result(&my_connection);
                j=mysql_num_rows(res_ptr1);
                if(j==0)
                {
                        printf("SELECT none image\n");
                        continue;
                }
                else
                {	
			printf("select changes from db of image");
                        while((sqlrow=mysql_fetch_row(res_ptr1)))
                        {
                                        strcpy(uid,sqlrow[0]);
                                        sprintf("select id,name,size,disk_format,checksum from images where id='%s'",uid);
                                        res=mysql_query(&my_connection,sql);
                                        if(res)
                                        {
                                                printf("SELECT error");
                                                return 0;
                                        }
                                        else
                                        {
                                                curid=atoi(sqlrow[1]);
                                                res_ptr=mysql_store_result(&my_connection);
                                                sqlrow=mysql_fetch_row(res_ptr);
                                                retval=get_image_from_dbres(&image,sqlrow);
                                                if(retval<0)
                                                        return -EINVAL;
						else
						{
							message=message_create("IMGI",NULL);
							if(message==NULL)
								return -EINVAL;
							if(IS_ERR(message))
								return -EINVAL;
							message_add_record(message,image);
							ret=sec_subject_sendmsg(sub_proc,message);
                					free(message);
						}	
                        		}
                	}
        	}
	mysql_free_result(res_ptr1);
        continue;
	}
	mysql_close(&my_connection);
        return 1;
}

int proc_send_imagepolicy(void * sub_proc,void * message)
{
	MESSAGE_HEAD * message_head;
	struct request_cmd * cmd;
	struct vm_policy * policy;
	int retval;
	int count=0;
	int i,j;
	int ret;

	char local_uuid[DIGEST_SIZE*2+1];
	char proc_name[DIGEST_SIZE*2+1];

	printf("begin to send imagepolicy!\n");

	ret=proc_share_data_getvalue("uuid",local_uuid);
	if(ret<0)
		return ret;
	ret=proc_share_data_getvalue("proc_name",proc_name);
	if(ret<0)
		return ret;

	message_head=get_message_head(message);

	// get  vm info from message
	retval=message_get_record(message,&cmd,0);
	if(retval<0)
		return -EINVAL;

	struct tcm_pcr_set * boot_pcrs;
	struct tcm_pcr_set * running_pcrs;
	ret=build_glance_image_policy(cmd->uuid,&boot_pcrs, &running_pcrs,&policy);
	if(policy==NULL)
		return -EEXIST;
	ExportPolicy("IMGP");	
	
	void * send_pcr_msg;
	void * send_msg;
	// send compute node's pcr policy
	send_pcr_msg=message_create("PCRP",message);
	message_add_record(send_pcr_msg,boot_pcrs);
	if(running_pcrs!=NULL)
		message_add_record(send_pcr_msg,running_pcrs);
		
	sec_subject_sendmsg(sub_proc,send_pcr_msg);

	send_msg=message_create("IMGP",message);
	message_add_record(send_msg,policy);
	sec_subject_sendmsg(sub_proc,send_msg);
	return 0;
}
