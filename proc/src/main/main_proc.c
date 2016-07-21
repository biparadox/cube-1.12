#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <dlfcn.h>

#include "../include/data_type.h"
#include "../include/struct_deal.h"
#include "../include/crypto_func.h"
#include "../include/valuename.h"
#include "../include/extern_struct.h"
#include "../include/extern_defno.h"
#include "../include/message_struct.h"
#include "../include/message_struct_desc.h"
#include "../include/vmlist.h"
#include "../include/connector.h"
#include "../include/logic_baselib.h"
#include "../include/connector.h"
#include "../include/sec_entity.h"
#include "../include/router.h"
#include "../include/openstack_trust_lib.h"
#include "../include/main_proc_init.h"

#include "main_proc_func.h"
#include "proc_config.h"

void * main_read_func(char * libname,char * sym)
{
    void * handle;	
    int (*func)(void *,void *);
    char * error;
    handle=dlopen(libname,RTLD_NOW);
     if(handle == NULL)		
     {
    	fprintf(stderr, "Failed to open library %s error:%s\n", libname, dlerror());
    	return NULL;
     }
     func=dlsym(handle,sym);
     if(func == NULL)		
     {
    	fprintf(stderr, "Failed to open func %s error:%s\n", sym, dlerror());
    	return NULL;
     }
     return func;
}     	


static char connector_config_file[DIGEST_SIZE*2]="./connector_config.cfg";
static char router_config_file[DIGEST_SIZE*2]="./router_policy.cfg";
static char plugin_config_file[DIGEST_SIZE*2]="./plugin_config.cfg";
static char main_config_file[DIGEST_SIZE*2]="./main_config.cfg";
static char audit_file[DIGEST_SIZE*2]="./message.log";
static char connector_plugin_file[DIGEST_SIZE*2]="plugin/libconnector_process_func.so";
static char router_plugin_file[DIGEST_SIZE*2]="plugin/librouter_process_func.so";


int main(int argc,char **argv)
{

    struct tcloud_connector_hub * hub;
    struct tcloud_connector * temp_conn;
    int ret;
    int retval;
    void * message_box;
    int i,j;
    int argv_offset;	

    void * main_proc; // point to the main proc's subject struct
    void * conn_proc; // point to the conn proc's subject struct
    void * router_proc; // point to the conn proc's subject struct
    char local_uuid[DIGEST_SIZE*2];

    FILE * fp;
    char audit_text[4096];
    char buffer[4096];
    void * root_node;
    void * temp_node;
    int json_offset;

    // process the command argument
    if(argc>=2)
    {
	argv_offset=1;
	if(argc%2!=1)
	{
		printf("error format! should be %s [-m main_cfgfile] [-p plugin_cfgfile]"
			"[-c connect_cfgfile] [-r router_cfgfile] [-a audit_file]!\n",argv[0]);
		return -EINVAL;
	}
    }
      
    for(argv_offset=1;argv_offset<argc;argv_offset+=2)
    {
	if((argv[argv_offset][0]!='-')
		&&(strlen(argv[argv_offset])!=2))
	{
		printf("error format! should be %s [-m main_cfgfile] [-p plugin_cfgfile]"
			"[-c connect_cfgfile] [-r router_cfgfile] [-a audit_file]!\n",argv[0]);
		return -EINVAL;
	}
	switch(argv[argv_offset][1])
	{
		case 'm':
			if(strlen(argv[argv_offset+1])>=DIGEST_SIZE*2)
				return -EINVAL;
			strncpy(main_config_file,argv[argv_offset+1],DIGEST_SIZE*2);
			break;			
		case 'p':
			if(strlen(argv[argv_offset+1])>=DIGEST_SIZE*2)
				return -EINVAL;
			strncpy(plugin_config_file,argv[argv_offset+1],DIGEST_SIZE*2);
			break;			
		case 'c':
			if(strlen(argv[argv_offset+1])>=DIGEST_SIZE*2)
				return -EINVAL;
			strncpy(connector_config_file,argv[argv_offset+1],DIGEST_SIZE*2);
			break;			
		case 'r':
			if(strlen(argv[argv_offset+1])>=DIGEST_SIZE*2)
				return -EINVAL;
			strncpy(router_config_file,argv[argv_offset+1],DIGEST_SIZE*2);
			break;			
		case 'a':
			if(strlen(argv[argv_offset+1])>=DIGEST_SIZE*2)
				return -EINVAL;
			strncpy(audit_file,argv[argv_offset+1],DIGEST_SIZE*2);
			break;			
		default:
			printf("error format! should be %s [-m main_cfgfile] [-p plugin_cfgfile]"
				"[-c connect_cfgfile] [-r router_cfgfile] [-a audit_file]!\n",argv[0]);
			return -EINVAL;
	
	}
    }	


    int fd =open(audit_file,O_CREAT|O_RDWR|O_TRUNC,0666);
    close(fd);

    // init system
    system("mkdir lib");
    openstack_trust_lib_init();
    sec_respool_list_init();
    // init the main proc struct
    struct main_config main_initpara;
    fd=open(main_config_file,O_RDONLY);
    if(fd<0)
	return -EINVAL;

    json_offset=read(fd,buffer,4096);
    if(json_offset<0)
	return ret;
    if(json_offset>4096)
    {
	printf("main config file is too long!\n");
	return -EINVAL;
    }
    close(fd);
    ret=json_solve_str(&root_node,buffer);
    if(ret<0)
	return ret;	
    void * struct_template=create_struct_template(&main_config_desc);
    if(struct_template==NULL)
    {
	printf("Fatal error!\n");
	return -EINVAL;
    }
    ret=json_2_struct(root_node,&main_initpara,struct_template);
    if(ret<0)
    {
	printf("main config file format error!\n");
	return -EINVAL;
     }
     free_struct_template(struct_template); 
    
    ret=sec_subject_create(main_initpara.proc_name,PROC_TYPE_MAIN,NULL,&main_proc);
    if(ret<0)
    	return ret;

    // init the proc's main share data
    ret=proc_share_data_init(share_data_desc);
    ret=get_local_uuid(local_uuid);
    printf("this machine's local uuid is %s\n",local_uuid);
    proc_share_data_setvalue("uuid",local_uuid);
    proc_share_data_setvalue("proc_name",main_initpara.proc_name);

    // do the main proc's init function
    void * initfunc =main_read_func(main_initpara.init_dlib,main_initpara.init_func);
    if(initfunc==NULL)
	return -EINVAL;
    sec_subject_setinitfunc(main_proc,initfunc);
    sec_subject_setstartfunc(main_proc,NULL);
	
    // init all the proc database

    usleep(time_val.tv_usec);

    for(i=0;procdb_init_list[i].name!=NULL;i++)
    {
	    PROCDB_INIT * db_init=&procdb_init_list[i];
	    if(db_init->record_desc!=NULL)
	    {
		    retval=register_record_type(db_init->name,db_init->record_desc);
		    if(retval<0)
			    return -EINVAL;
	    }
		
	    if(db_init->recordlib_ops!=NULL)
	    {
	   	 retval=register_policy_lib(db_init->name,db_init->recordlib_ops);
	  	 if(retval<0)
	         {
		    printf("register lib %s error!\n",db_init->name);
		    return retval;
	    	 }
	         retval=db_init->init(db_init->name,NULL);
		 if(retval<0)
			return -EINVAL;
	    	 retval=LoadPolicy(db_init->name);
	    }
    }

    sec_subject_init(main_proc,main_initpara.proc_name);
		
    PROC_INIT plugin_proc; 

    // init the connect proc	
    plugin_proc.init =main_read_func(connector_plugin_file,"proc_conn_init");
    if(plugin_proc.init==NULL)
	return -EINVAL;
    plugin_proc.start =main_read_func(connector_plugin_file,"proc_conn_start");
    if(plugin_proc.start==NULL)
	return -EINVAL;
     plugin_proc.name=dup_str("connector_proc",0);	
     plugin_proc.type=PROC_TYPE_CONN;
	
     ret=sec_subject_create("connector_proc",PROC_TYPE_CONN,NULL,&conn_proc);
    if(ret<0)
	    return ret;

    sec_subject_setinitfunc(conn_proc,plugin_proc.init);
    sec_subject_setstartfunc(conn_proc,plugin_proc.start);

    sec_subject_init(conn_proc,connector_config_file);

    add_sec_subject(conn_proc);

    // init the router proc	
    plugin_proc.init =main_read_func(router_plugin_file,"proc_router_init");
    if(plugin_proc.init==NULL)
	return -EINVAL;
    plugin_proc.start =main_read_func(router_plugin_file,"proc_router_start");
    if(plugin_proc.start==NULL)
	return -EINVAL;
     plugin_proc.name=dup_str("router_proc",0);	
     plugin_proc.type=PROC_TYPE_ROUTER;
	
    ret=sec_subject_create("router_proc",PROC_TYPE_MONITOR,NULL,&router_proc);
    if(ret<0)
	    return ret;

    sec_subject_setinitfunc(router_proc,plugin_proc.init);
    sec_subject_setstartfunc(router_proc,plugin_proc.start);

    sec_subject_init(router_proc,router_config_file);
	
    printf("prepare the router proc\n");
    ret=sec_subject_start(router_proc,NULL);
    if(ret<0)
	    return ret;

    // loop to init all the plugin's 
    fd=open(plugin_config_file,O_RDONLY);
    if(fd<0)
	return -EINVAL;

    json_offset=read(fd,buffer,4096);
    char * json_str=buffer;
    int json_left=json_offset;
    struct plugin_config plugin_initpara; 
    void * sub_proc;
    struct_template=create_struct_template(&plugin_config_desc);
    if(struct_template == NULL)
    {
	printf("fatal error!\n");
	return -EINVAL;
    }
    
    while(json_left>DIGEST_SIZE/2)
    {
	ret=json_solve_str(&root_node,json_str);
	if(ret<0)
	{
		printf("read plugin config failed!\n");
		break;		
	}	
	json_offset+=ret;
	json_str=buffer+json_offset;
	json_left-=ret;
        ret=json_2_struct(root_node,&plugin_initpara,struct_template);
	if(ret<0)
	{
		printf("plugin config format error!\n");
		break;		
	}		
       	ret=sec_subject_create(plugin_initpara.name,plugin_initpara.type,NULL,&sub_proc);
   	if(ret<0)
		return ret;

    	plugin_initpara.init =main_read_func(plugin_initpara.plugin_dlib,plugin_initpara.init);
    	if(plugin_initpara.init==NULL)
		return -EINVAL;
    	plugin_initpara.start =main_read_func(plugin_initpara.plugin_dlib,plugin_initpara.start);
    	if(plugin_initpara.start==NULL)
		return -EINVAL;

    	sec_subject_setinitfunc(sub_proc,plugin_initpara.init);
   	sec_subject_setstartfunc(sub_proc,plugin_initpara.start);
  	ret= sec_subject_init(sub_proc,NULL);
	if(ret<0)
  		return ret;
        add_sec_subject(sub_proc);
    }
     
    usleep(time_val.tv_usec);
    printf("prepare the conn proc\n");
    ret=sec_subject_start(conn_proc,NULL);
    if(ret<0)
	    return ret;

    // second loop:  start all the monitor process
       	
    ret=get_first_sec_subject(&sub_proc);

    if(ret<0)
	return ret;
    while(sub_proc!=NULL)
    {
	  if(sec_subject_gettype(sub_proc) == PROC_TYPE_MONITOR)
	  {
  		ret=sec_subject_start(sub_proc,NULL);
	  	if(ret<0)
  			return ret;
		printf("monitor sub_proc %s started successfully!\n",sec_subject_getname(sub_proc));
	  }
    	  ret=get_next_sec_subject(&sub_proc);

    	  if(ret<0)
		return ret;
    }


    int thread_retval;
    ret=sec_subject_join(conn_proc,&thread_retval);
    printf("thread return value %d!\n",thread_retval);

    return ret;
}
