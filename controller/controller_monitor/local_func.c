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

#include "readconfig.h"
#include "local_func.h"

#define MBR_PCR_INDEX  4
#define KERNEL_PCR_INDEX  10
#define SECURE_PCR_INDEX  11
#define VMM_PCR_INDEX  12
#define TRUSTBUS_PCR_INDEX  13
#define EXPAND_PCR_INDEX  23

static char * boot_file_list[] =
{
	"/boot/vmlinuz-3.5.0-18-generic",
	"/boot/initrd.img-3.5.0-18-generic",
	NULL
};
static char * trustbus_file_list[] =
{
	"/root/cube-1.0/proc/compute/compute_monitor/compute_monitor",
	"/root/cube-1.0/proc/compute/compute_monitor/main_proc_policy.cfg",
	NULL
};
static char * kvm_file_list[] =
{
	"/etc/kvm/kvm-ifup",
	"/etc/kvm/kvm-ifdown",
	"/usr/bin/qemu-system-x86_64",
	"/usr/bin/nova-compute",
	NULL
};
static char * os_sec_file_list[] =
{
	"/boot/os_safe.d/os_sec.ko",
	"/boot/os_safe.d/whitelist",
	NULL
};

struct  pcr_index_filelist
{
	int pcr_index;
	char * tail_desc;
	char ** filelist;
	int trust_level
} ;


static struct pcr_index_filelist compute_pcr_filelist[] =
{
	{KERNEL_PCR_INDEX,":kernel and initrd",boot_file_list,2},
	{TRUSTBUS_PCR_INDEX,":trustbus cube-1.0",trustbus_file_list,2},
	{VMM_PCR_INDEX,":kvm with qemu",kvm_file_list,2},
	{0,NULL}
};
static struct pcr_index_filelist image_pcr_filelist[] =
{
	{SECURE_PCR_INDEX,":os_sec and its whitelist",os_sec_file_list,1},
	{0,NULL}
};
static struct pcr_index_filelist vm_pcr_filelist[] =
{
	{SECURE_PCR_INDEX,":os_sec and its whitelist",os_sec_file_list,1},
	{0,NULL}
};

int get_image_from_dbres(void * image_info, void * res)
{
	MYSQL_ROW sqlrow;
	sqlrow=(MYSQL_ROW)res;

	struct image_info * image;
	image=(struct image_info *)image_info;
	if(image==NULL)
		return -EINVAL;

	strcpy(image->uuid,sqlrow[0]);
//	strcpy(uid,sqlrow[0]);
	image->image_name=malloc(strlen(sqlrow[1])+1);
	if(image->image_name==NULL)
		return -ENOMEM;
	strcpy(image->image_name,sqlrow[1]);
	image->image_size=atol(sqlrow[2]);
	image->image_disk_format=malloc(strlen(sqlrow[3])+1);
	if(image->image_disk_format==NULL)
		return -ENOMEM;
	strcpy(image->image_disk_format,sqlrow[3]);
	image->image_checksum=malloc(strlen(sqlrow[4])+1);
	if(image->image_checksum==NULL)
		return -ENOMEM;
	strcpy(image->image_checksum,sqlrow[4]);
	return 0;
}

int get_user_from_dbres(void * user_info, void * res)
{
	MYSQL_ROW sqlrow;
	sqlrow=(MYSQL_ROW)res;

	struct openstack_user * user;
	user=(struct openstack_user *)user_info;
	if(user==NULL)
		return -EINVAL;
	strncpy(user->uuid,sqlrow[0],DIGEST_SIZE*2);

	user->name=malloc(strlen(sqlrow[1])+1);
	if(user->name==NULL)
		return -ENOMEM;
	strcpy(user->name,sqlrow[1]);
	return 0;
}

int get_platform_from_dbres(void * platform_info, void * res)
{
	MYSQL_ROW sqlrow;
	sqlrow=(MYSQL_ROW)res;

	struct platform_info * platform;
	platform=(struct platform_info *)platform_info;
	if(platform==NULL)
		return -EINVAL;
        memset(platform_info,0,sizeof(struct platform_info));

	platform->name=dup_str(sqlrow[0],0);
	platform->hype_ver=dup_str(sqlrow[1],0);
	platform->hypervisor=dup_str(sqlrow[2],0);
	return 0;
}

int get_vm_from_dbres(void * vm_info, void * db_res,void * sql_connection)
{

	MYSQL * my_connection;
        MYSQL_RES * res_ptr;
        MYSQL_RES * res_ptr1;
	MYSQL_ROW sqlrow;
	sqlrow=(MYSQL_ROW)db_res;
	my_connection=(MYSQL *)sql_connection;


	struct vm_info * vm;
        char temp[256];
        char uid[256];
        char key[256];
        char sql[256];
	int res;
	int i,j;
	int curid;
	vm=(struct vm_info *)vm_info;
	if(vm==NULL)
		return -EINVAL;
	memset(vm,0,sizeof(struct vm_info));

	if (mysql_select_db(my_connection, "nova"))
	{
		printf("CONNECTION database glance FAILED\n");
		return -EINVAL;
	}
	strcpy(uid,sqlrow[0]);
	// get info from instances db and compute_nodes db
	sprintf(sql,"select p1.uuid,p1.memory_mb,p1.vcpus,p1.root_device_name,"
		"p2.hypervisor_type ,p1.image_ref, p1.id FROM instances AS p1,"
	  	"compute_nodes as p2 WHERE p1.uuid='%s' and p1.host=p2.hypervisor_hostname order by p1.id",uid);
	res=mysql_query(my_connection,sql); //此处为选择语句，根据相关数据字段添加
	if(res)
	{
		printf("SELECT error %d!\n",res);
		return -EEXIST;
	}
	res_ptr=mysql_store_result(my_connection);
	sqlrow=mysql_fetch_row(res_ptr);
	strcpy(vm->uuid,sqlrow[0]);
	vm->memory=atol(sqlrow[1])*1024;
	vm->vcpu=atoi(sqlrow[2]);
	strcpy(temp,sqlrow[3]);
	vm->diskinfo.dev=malloc(strlen(temp)-4);
	if(vm->diskinfo.dev==NULL)
         	return -ENOMEM;
	strcpy(vm->diskinfo.dev,&(temp[5]));
	strcpy(temp,sqlrow[4]);
	j=strlen(temp);
	 for(i=0;i<j;i++)    
	{
		temp[i]=tolower(temp[i]);
	}
	vm->diskinfo.name=malloc(strlen(temp)+1);
	if(vm->diskinfo.name==NULL)
		return -ENOMEM;
	strcpy(vm->diskinfo.name,temp);
	strcpy(key,sqlrow[5]);
	curid=atoi(sqlrow[6]);
	mysql_free_result(res_ptr);

	sprintf(sql,"select address from virtual_interfaces where instance_uuid='%s' ",vm->uuid);
	res=mysql_query(my_connection,sql);
	if(res)
	{
		printf("SELECT error: %s\n,",mysql_error(my_connection));
	}
	res_ptr=mysql_store_result(my_connection);
	sqlrow=mysql_fetch_row(res_ptr);
	if(sqlrow!=NULL)
	{

		vm->network.macadd=malloc(strlen(sqlrow[0])+1);
     		if(vm->network.macadd==NULL)
            	   return -ENOMEM;
		strcpy(vm->network.macadd,sqlrow[0]);
	}
		mysql_free_result(res_ptr);

	// get image information from glance database
	//
	if (mysql_select_db(my_connection, "glance"))
	{
		printf("CONNECTION database glance FAILED\n");
		return -EINVAL;
	}
	
	sprintf(sql,"select disk_format from images where id ='%s' ",key);
	res=mysql_query(my_connection,sql);
	
	if(res)
	{
		printf("SELECT error: %s\n,",mysql_error(my_connection));
		return -EINVAL;
	}
	res_ptr=mysql_store_result(my_connection);
	sqlrow=mysql_fetch_row(res_ptr);
	vm->diskinfo.type=malloc(strlen(sqlrow[0])+1);
        if(vm->diskinfo.type==NULL)
        	return -ENOMEM;
	strcpy(vm->diskinfo.type,sqlrow[0]);
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
	mysql_free_result(res_ptr);

	return 0;
}

