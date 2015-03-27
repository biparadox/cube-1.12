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
#include <mysql/mysql.h>

#include "../include/data_type.h"
#include "../include/struct_deal.h"
#include "../include/crypto_func.h"
#include "../include/extern_struct.h"
#include "../include/extern_defno.h"
#include "../include/message_struct.h"
#include "../include/vmlist.h"
#include "../include/vtpm_struct.h"
#include "../include/vm_policy.h"
#include "../include/connector.h"
#include "../include/logic_baselib.h"
#include "../include/connector.h"
#include "../include/sec_entity.h"
#include "../include/tesi.h"
#include "../include/main_proc_init.h"

#include "cloud_config.h"
#include "main_proc_func.h"
#include "proc_config.h"

struct main_proc_pointer
{
	MYSQL my_connection;
};

int controller_monitor_init(void * proc,void * para)
{
	int ret;
	char local_uuid[DIGEST_SIZE*2];
	
	system("mkdir ./mnt");
	struct main_proc_pointer * main_pointer;
	main_pointer= malloc(sizeof(struct main_proc_pointer));
	if(main_pointer==NULL)
		return -ENOMEM;
        ret=get_local_uuid(local_uuid);
        printf("this machine's local uuid is %s\n",local_uuid);
	proc_share_data_setvalue("local_uuid",local_uuid);
	proc_share_data_setvalue("proc_name",para);

	MYSQL * mysql =&(main_pointer->my_connection);	
        mysql_init(mysql);
         if(!mysql_real_connect(mysql,"127.0.0.1","root","openstack",NULL,0,NULL,0))
//        if(!mysql_real_connect(mysql,"172.21.5.8","root","openstack",NULL,3306,NULL,0))
//   if(!mysql_real_connect(&my_connection,"10.46.169.7","root","openstack",NULL,3306,NULL,0))
   	{
		printf("CONNECTION FAILED\n");
		free(main_pointer);
		return -EINVAL;
   	}

	proc_share_data_setpointer(main_pointer);
	sec_subject_register_statelist(proc,main_state_list);
	build_image_mount_respool(0,7,"image_mntpoint");
	return 0;
}

int platform_info_memdb_init()
{
	struct platform_info * platform_info;
	MYSQL * my_connection;
	MYSQL_RES * res_ptr;
	MYSQL_ROW sqlrow;

	struct platform_info * platform;
        int retval;
        BYTE digest[DIGEST_SIZE];
        char buffer[4096];
        int offset;        void * info_template;
	int blob_size;
	int res;
	char sql[256];


	struct  main_proc_pointer * pointer=proc_share_data_getpointer();
	my_connection=&(pointer->my_connection);
        if (mysql_select_db(my_connection, "nova"))
        {
                printf("CONNECTION database FAILED\n");
        }
	sprintf(sql,"select hypervisor_hostname,hypervisor_version,hypervisor_type from compute_nodes where deleted_at is NULL");
	res=mysql_query(my_connection,sql);

        if(res)
        {
                printf("SELECT error");
                return 0;
        }

        res_ptr=mysql_store_result(my_connection);
	while((sqlrow=mysql_fetch_row(res_ptr)))
	{
		platform=malloc(sizeof(struct platform_info));
		if(platform == NULL)
			return -ENOMEM;
		retval=get_platform_from_dbres(platform,sqlrow);
		if(retval<0)
			return -EINVAL;
       		AddPolicy(platform,"PLAI");
	}
	mysql_free_result(res_ptr);
	
        ExportPolicyToFile("./lib/PLAI.lib","PLAI");
	return 0;
}

int image_info_memdb_init()
{
    	MYSQL * my_connection;
   	MYSQL_RES * res_ptr;
	MYSQL_ROW sqlrow;

        struct image_info * image;
        int retval;
        BYTE digest[DIGEST_SIZE];
        char buffer[4096];
        int offset;
        void * info_template;
	int blob_size;

	struct  main_proc_pointer * pointer=proc_share_data_getpointer();
	my_connection=&(pointer->my_connection);


	
	// in the test mode test function: we should get data from file
	//
	if (mysql_select_db(my_connection, "glance"))
	{
		printf("CONNECTION database FAILED\n");
		return -EEXIST;
	}
	char  sql[256];
	int res;

	strcpy(sql,"select id,name,size,disk_format,checksum from images where status='active'");
	res=mysql_query(my_connection,sql);
	if(res)
	{
		printf("SELECT error");
		return 0;
	}
	res_ptr=mysql_store_result(my_connection);
	while((sqlrow=mysql_fetch_row(res_ptr)))
	{
		image=malloc(sizeof(struct image_info));
		if(image==NULL)
			return -ENOMEM;
        	memset(image,0,sizeof(struct image_info));
		retval=get_image_from_dbres(image,sqlrow);
		if(retval<0)
			return -EINVAL;
       		AddPolicy(image,"IMGI");
	}
	mysql_free_result(res_ptr);
	
        ExportPolicy("IMGI");
        return ;
}

int vm_info_memdb_init()
{
    	MYSQL * my_connection;
   	MYSQL_RES * res_ptr;
        MYSQL_RES * res_ptr1;
	MYSQL_ROW sqlrow;

        struct vm_info * vm;
        int retval;
        BYTE digest[DIGEST_SIZE];
        char buffer[4096];
        int offset;
        void * info_template;
	int blob_size;

	struct  main_proc_pointer * pointer=proc_share_data_getpointer();
	my_connection=&(pointer->my_connection);
	
	if (mysql_select_db(my_connection, "nova"))
	{
		printf("CONNECTION database FAILED\n");
		return -EEXIST;
	}

	char  sql[512];
	int res;
	int curid;
        char uid[256];
        sprintf(sql,"select uuid from instances where deleted_at is NULL",curid);
	res=mysql_query(my_connection,sql);
        res_ptr1=mysql_store_result(my_connection);
       	retval=mysql_num_rows(res_ptr1);
        if(retval==0)
        {
		printf("SELECT none\n");
		return -EEXIST;
        }
	while((sqlrow=mysql_fetch_row(res_ptr1)))
	{
		vm=malloc(sizeof(struct vm_info));
		if(vm==NULL)
			return -ENOMEM;
        	memset(vm,0,sizeof(struct vm_info));
		get_vm_from_dbres(vm,sqlrow,my_connection);
		AddPolicy(vm,"VM_I");
	}

        ExportPolicy("VM_I");
        return ;
}
int image_policy_memdb_init()
{

        struct image_info * image;
        struct vm_policy * image_policy;
	struct tcm_pcr_set * boot_pcrs;
	struct tcm_pcr_set * runtime_pcrs;
        int retval;
        BYTE digest[DIGEST_SIZE];
        char buffer[4096];
        int offset;
        void * policy_template;

	int i=0;
	image=GetFirstPolicy("IMGI");

	
	while(image!=NULL)
	{
		retval=build_glance_image_policy(image->uuid,&boot_pcrs,&runtime_pcrs,&image_policy);			
		image=GetNextPolicy("IMGI");
		AddPolicy(boot_pcrs,"PCRP");
		AddPolicy(runtime_pcrs,"PCRP");
	}
        ExportPolicy("PCRP");
        ExportPolicy("IMGP");
        return ;
}
int vm_policy_memdb_init(void * conn)
{
}
int platform_policy_memdb_init(void * conn)
{
}
