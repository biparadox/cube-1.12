#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
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
#include "../include/connector.h"
#include "../include/logic_baselib.h"
#include "../include/connector.h"
#include "../include/sec_entity.h"
#include "../include/router.h"
#include "../include/openstack_trust_lib.h"
#include "../include/main_proc_init.h"

#include "../cloud_config.h"
#include "main_proc_func.h"
#include "proc_config.h"


int main()
{

    struct tcloud_connector_hub * hub;
    struct tcloud_connector * temp_conn;
    int ret;
    int retval;
    void * message_box;
    int i,j;

    void * main_proc; // point to the main proc's subject struct
    void * conn_proc; // point to the conn proc's subject struct
    void * router_proc; // point to the conn proc's subject struct

    const char * audit_filename= "./message.log";
    FILE * fp;
    char audit_text[65536];
    int fd =open(audit_filename,O_CREAT|O_RDWR|O_TRUNC);
    close(fd);

    system("mkdir lib");
    openstack_trust_lib_init();
    sec_respool_list_init();
    // init the main proc struct
    ret=sec_subject_create(main_proc_initdata.name,PROC_TYPE_MAIN,NULL,&main_proc);
    if(ret<0)
    	return ret;
    // create subject's statelist
    if(main_proc_initdata.statelist!=NULL)
    {
  	  ret=sec_subject_create_statelist(main_proc, main_proc_initdata.statelist);  
	  if(ret<0)
    		return ret;
    }

    // create subject's funclist
    if(main_proc_initdata.funclist!=NULL)
    {
   	 ret=sec_subject_create_funclist(main_proc, main_proc_initdata.funclist);  
 	 if(ret<0)
    		return ret;
    }
    // init the proc's main share data
    ret=proc_share_data_init(share_data_desc);

    // do the main proc's init function
    sec_subject_setinitfunc(main_proc,main_proc_initdata.init);
    sec_subject_setstartfunc(main_proc,main_proc_initdata.start);
    sec_subject_init(main_proc,main_proc_initdata.name);
	
    // init all the proc database


    usleep(time_val.tv_usec);

    for(i=0;procdb_init_list[i].name!=NULL;i++)
    {
	    PROCDB_INIT * db_init=&procdb_init_list[i];
	    retval=register_lib(db_init->name);
	    if(retval<0)
	    {
		    printf("register lib %s error!\n",db_init->name);
		    return retval;
	    }
		// if lib file exists, we should load this lib
	    retval=LoadPolicy(db_init->name);
	
	    // else, we should init it
//	    if((retval <=0) &&(db_init->init!=NULL))
	    if(db_init->init!=NULL)
	    {
	         retval=db_init->init();
		 if(retval<0)
			return -EINVAL;
	    }
	    if(db_init->proc_state!=0)
	    {
    		proc_share_data_setstate(db_init->proc_state);
	    }
    }
		

    // init the connect proc	
    ret=sec_subject_create("connector_proc",PROC_TYPE_CONN,NULL,&conn_proc);
    if(ret<0)
	    return ret;

    sec_subject_setinitfunc(conn_proc,conn_proc_initdata.init);
    sec_subject_setstartfunc(conn_proc,conn_proc_initdata.start);


   struct conn_init_para * conn_init_para = malloc(sizeof(struct conn_init_para));
   if(conn_init_para ==NULL)
	return -ENOMEM;
  
    //conn_init_para->hub=hub;
    //conn_init_para->default_local_port=default_local_port;
    //conn_init_para->default_remote_port=default_remote_port;
 
    sec_subject_init(conn_proc,conn_init_para);
    free(conn_init_para);

    add_sec_subject(conn_proc);

    // init the router proc	
    ret=sec_subject_create("router_proc",PROC_TYPE_MONITOR,NULL,&router_proc);
    if(ret<0)
	    return ret;

    sec_subject_setinitfunc(router_proc,router_proc_initdata.init);
    sec_subject_setstartfunc(router_proc,router_proc_initdata.start);

    sec_subject_init(router_proc,NULL);
	
    printf("prepare the router proc\n");
    ret=sec_subject_start(router_proc,NULL);
    if(ret<0)
	    return ret;
   // first loop: init all the subject
    for(i=0;proc_init_list[i].name!=NULL;i++)
    {
	  void * sub_proc;
       	  ret=sec_subject_create(proc_init_list[i].name,proc_init_list[i].type,NULL,&sub_proc);
   	  if(ret<0)
		    return ret;

    	  ret=add_sec_subject(sub_proc);
	  void * sub_proc1;
	  ret=find_sec_subject(proc_init_list[i].name,&sub_proc1);
	  if(ret<0)
		  return ret;
	  if(sub_proc1==NULL)
	  {
		  printf("create sub_proc %s failed!\n",proc_init_list[i].name);
		  return -EINVAL;
	  }
	  ret=sec_subject_create_statelist(sub_proc, proc_init_list[i].statelist);  
	  if(ret<0)
  		return ret;
	  ret=sec_subject_create_funclist(sub_proc, proc_init_list[i].funclist);  
	  if(ret<0)
  		return ret;
    	  sec_subject_setinitfunc(sub_proc,proc_init_list[i].init);
   	  sec_subject_setstartfunc(sub_proc,proc_init_list[i].start);
  	  sec_subject_init(sub_proc,NULL);

	  if(ret<0)
  		return ret;
    }	    

    usleep(time_val.tv_usec);

    // second loop:  start all the monitor process
    for(i=0;proc_init_list[i].name!=NULL;i++)
    {
	  void * sub_proc;
	  ret=find_sec_subject(proc_init_list[i].name,&sub_proc);
	  if(ret<0)
		  return ret;
	  if(sub_proc==NULL)
	  {
		  printf("create sub_proc %s failed!\n",proc_init_list[i].name);
		  return -EINVAL;
	  }
	  if(sec_subject_gettype(sub_proc) == PROC_TYPE_MONITOR)
	  {
  		ret=sec_subject_start(sub_proc,NULL);
	  	if(ret<0)
  			return ret;
		printf("monitor sub_proc %s started successfully!\n",sec_subject_getname(sub_proc));
	 }
    }	    

 
    printf("prepare the conn proc\n");
    ret=sec_subject_start(conn_proc,NULL);
    if(ret<0)
	    return ret;

    int thread_retval;
    ret=sec_subject_join(conn_proc,&thread_retval);
    printf("thread return value %d!\n",thread_retval);

    if(ret<0)
	return ret;
}
