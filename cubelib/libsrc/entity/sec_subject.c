#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <pthread.h>

#include "../include/data_type.h"
#include "../include/kernel_comp.h"
#include "../include/list.h"
#include "../include/attrlist.h"
#include "../include/struct_deal.h"
#include "../include/extern_defno.h"
#include "../include/extern_struct.h"
//#include "../include/extern_struct_desc.h"
#include "../include/message_struct.h"
//#include "../include/message_struct_desc.h" 
#include "../include/connector.h"
#include "../include/logic_baselib.h"
#include "../include/policy_ui.h"
#include "../include/sec_entity.h"
#include "../include/valuename.h"

extern struct proc_secure_object;
typedef struct proc_secure_object SEC_OBJECT;

typedef struct proc_secure_subject
{
	char name[DIGEST_SIZE*2];
	char uuid[DIGEST_SIZE*2];
	int type;
	int proc_state;
	int fsm_state;
	pthread_t proc_thread; 
	pthread_attr_t thread_attr; 
	pthread_mutex_t mutex;
	pthread_cond_t cond;
//	int state;
	void * recv_queue;
	void * send_queue;
	SEC_OBJECT * context;
	int retval;
	NAME2VALUE * statename;
	NAME2POINTER * funcname;
	void * proc_policy;
	void * head_template;
	int  (*init)(void *,void *);
	int  (*start)(void *,void *);
}__attribute__((packed)) SEC_SUBJECT;

struct secure_subject_list
{
	int state;
	pthread_rwlock_t rwlock;
	Record_List head;
	struct list_head * curr;
}; 

static struct secure_subject_list * sec_subject_list;

enum sec_subject_list_state
{
	SEC_SUBJECT_LIST_INIT,
	SEC_SUBJECT_LIST_ERR,
};

static struct struct_elem_attr sec_subject_head_desc[] =
{
	{"name",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"type",OS210_TYPE_ENUM,sizeof(int),sec_subject_type_valuelist},
	{"proc_state",OS210_TYPE_ENUM,sizeof(int),sec_proc_state_valuelist},
	{"fsm_state",OS210_TYPE_ENUM,sizeof(int),default_state_list},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

int sec_subject_list_init()
{
	int ret;
	sec_subject_list=kmalloc(sizeof(struct secure_subject_list),GFP_KERNEL);
	if(sec_subject_list==NULL)
		return -ENOMEM;
	INIT_LIST_HEAD(&(sec_subject_list->head.list));
	sec_subject_list->head.record=NULL;
	sec_subject_list->curr=&(sec_subject_list->head.list);
	ret=pthread_rwlock_init(&(sec_subject_list->rwlock),NULL);
	if(ret<0)
	{
		kfree(sec_subject_list);
		return -EINVAL;
	}
	return 0;
}

int find_sec_subject(char * name,void ** sec_sub)
{
	struct list_head * curr_head;
	Record_List * record_elem;
	Record_List * record_list;
	record_list=&(sec_subject_list->head);
	int ret;

	pthread_rwlock_rdlock(&(sec_subject_list->rwlock));
	curr_head = find_elem_with_tag(record_list,
		entity_comp_uuid,name);
	if(curr_head == NULL)
	{
		pthread_rwlock_unlock(&(sec_subject_list->rwlock));
		return 0;
	}
	if(IS_ERR(curr_head))
	{
		pthread_rwlock_unlock(&(sec_subject_list->rwlock));
		return curr_head;
	}
	record_elem=list_entry(curr_head,Record_List,list);
	pthread_rwlock_unlock(&(sec_subject_list->rwlock));
	*sec_sub=record_elem->record;
	return 1;	
}

int get_first_sec_subject(void **sec_sub)
{
	Record_List * recordhead;
	Record_List * newrecord;
	struct list_head * curr_head;

	pthread_rwlock_rdlock(&(sec_subject_list->rwlock));
	recordhead = &(sec_subject_list->head);
	if(recordhead==NULL)
	{
		pthread_rwlock_unlock(&(sec_subject_list->rwlock));
		*sec_sub=NULL;
		return 0;
	}
	curr_head = recordhead->list.next;
	sec_subject_list->curr = curr_head;
	newrecord = list_entry(curr_head,Record_List,list);
	pthread_rwlock_unlock(&(sec_subject_list->rwlock));
	*sec_sub=newrecord->record;
	return 1;
}

int get_next_sec_subject(void **sec_sub)
{
	Record_List * recordhead;
	Record_List * newrecord;
	struct list_head * curr_head;

	recordhead = &(sec_subject_list->head);
	if(recordhead==NULL)
	{
		*sec_sub=NULL;
		return 0;
	}
	pthread_rwlock_rdlock(&(sec_subject_list->rwlock));
	curr_head = sec_subject_list->curr->next;
	if(curr_head==recordhead)
	{
		*sec_sub=NULL;
		pthread_rwlock_unlock(&(sec_subject_list->rwlock));
		return 0;
	}
	sec_subject_list->curr = curr_head;
	newrecord = list_entry(curr_head,Record_List,list);
	pthread_rwlock_unlock(&(sec_subject_list->rwlock));
	*sec_sub=newrecord->record;
	return 1;
}

int add_sec_subject(void * sec_subject)
{
	Record_List * recordhead;
	Record_List * newrecord;

	recordhead = &(sec_subject_list->head);
	if(recordhead==NULL)
		return -ENOMEM;

	newrecord = kmalloc(sizeof(Record_List),GFP_KERNEL);
	if(newrecord==NULL)
		return -ENOMEM;
	INIT_LIST_HEAD(&(newrecord->list));
	newrecord->record=sec_subject;
	pthread_rwlock_wrlock(&(sec_subject_list->rwlock));
	list_add_tail(&(newrecord->list),recordhead);
	pthread_rwlock_unlock(&(sec_subject_list->rwlock));
	return 0;
}	

int remove_sec_subject(char * name,void **sec_sub)
{
	Record_List * recordhead;
	Record_List * record_elem;
	struct list_head * curr_head;
	void * record;

	recordhead = &(sec_subject_list->head);
	if(recordhead==NULL)
		return 0;

	pthread_rwlock_wrlock(&(sec_subject_list->rwlock));

	curr_head=find_elem_with_tag(recordhead,entity_comp_uuid,name);
	if(curr_head==NULL)
	{
		pthread_rwlock_unlock(&(sec_subject_list->rwlock));
		return 0;
	}
	record_elem=list_entry(curr_head,Record_List,list);
	list_del(curr_head);
	record=record_elem->record;
	kfree(record_elem);
        *sec_sub=record;	
	return 1;
}	

 
int sec_subject_create(char * name,int type,struct struct_elem_attr *  context_desc, void ** sec_sub)
{
	int ret;
	SEC_SUBJECT * sec_subject;
	if(name==NULL)
		return -EINVAL;


	// alloc mem for sec_subject
	sec_subject=kmalloc(sizeof(SEC_SUBJECT),GFP_KERNEL);
	if(sec_subject==NULL)
		return -ENOMEM;
	memset(sec_subject,0,sizeof(SEC_SUBJECT));

	// assign some  value for sec_subject
	strncpy(sec_subject->name,name,DIGEST_SIZE*2);
	sec_subject->type=type;

	// init the proc's mutex and the cond
	ret=pthread_mutex_init(&(sec_subject->mutex),NULL);
	if(ret!=0)
	{
		kfree(sec_subject);
		return -EINVAL;
	}
	ret=pthread_cond_init(&(sec_subject->cond),NULL);
	if(ret!=0)
	{
		pthread_mutex_destroy(&(sec_subject->mutex));
		kfree(sec_subject);
		return -EINVAL;
	}

	// init the send message queue and the receive message queue 
	ret=message_queue_init(&(sec_subject->recv_queue));
	if(ret<0)
	{
		pthread_mutex_destroy(&(sec_subject->mutex));
		pthread_cond_destroy(&(sec_subject->cond));
		kfree(sec_subject);
		return -EINVAL;
	}
	ret=message_queue_init(&(sec_subject->send_queue));
	if(ret<0)
	{
		message_queue_destroy(&(sec_subject->recv_queue));
		pthread_mutex_destroy(&(sec_subject->mutex));
		pthread_cond_destroy(&(sec_subject->cond));
		kfree(sec_subject);
		return -EINVAL;
	}

	// init the subject's context( it is an sec object)

	sec_subject->context=sec_object_init(name,context_desc);
	if(sec_subject->context==NULL)
	{
		message_queue_destroy(&(sec_subject->send_queue));
		message_queue_destroy(&(sec_subject->recv_queue));
		pthread_mutex_destroy(&(sec_subject->mutex));
		pthread_cond_destroy(&(sec_subject->cond));
		kfree(sec_subject);
		return ret;
	}		
	*sec_sub=sec_subject;		
	sec_subject->proc_state=SEC_PROC_CREATE;
	sec_subject->head_template=create_struct_template(sec_subject_head_desc);
	if(sec_subject->head_template==NULL)
	{
		remove_sec_object(sec_subject->context);
		message_queue_destroy(&(sec_subject->send_queue));
		message_queue_destroy(&(sec_subject->recv_queue));
		pthread_mutex_destroy(&(sec_subject->mutex));
		pthread_cond_destroy(&(sec_subject->cond));
		kfree(sec_subject);
		return ret;

	}

	pthread_attr_init(&(sec_subject->thread_attr));
	sec_subject->init=NULL;
	sec_subject->start=NULL;

	return 0;
}

int sec_subject_setinitfunc(void * sec_sub,void * init)
{
	int ret;
	SEC_SUBJECT * sec_subject;
	if(sec_sub==NULL)
		return -EINVAL;
	sec_subject = (SEC_SUBJECT *)sec_sub;
	sec_subject->init=init;
	return 0;
}



int sec_subject_setstartfunc(void * sec_sub,void * start)
{
	int ret;
	SEC_SUBJECT * sec_subject;
	if(sec_sub==NULL)
		return -EINVAL;
	sec_subject = (SEC_SUBJECT *)sec_sub;
	sec_subject->start=start;
	return 0;
}

void * sec_subject_getheadtemplate(void * sec_sub)
{
	int ret;
	SEC_SUBJECT * sec_subject;
	if(sec_sub==NULL)
		return -EINVAL;
	sec_subject = (SEC_SUBJECT *)sec_sub;

	return sec_subject->head_template;
}

int sec_subject_gettype(void * sec_sub)
{
	int ret;
	SEC_SUBJECT * sec_subject;
	if(sec_sub==NULL)
		return -EINVAL;
	sec_subject = (SEC_SUBJECT *)sec_sub;

	return sec_subject->type;
}

int sec_subject_getprocstate(void * sec_sub)
{
	int ret;
	SEC_SUBJECT * sec_subject;
	if(sec_sub==NULL)
		return -EINVAL;
	sec_subject = (SEC_SUBJECT *)sec_sub;

	return sec_subject->proc_state;
}

void * sec_subject_getname(void * sec_sub)
{
	int ret;
	SEC_SUBJECT * sec_subject;
	if(sec_sub==NULL)
		return NULL;
	sec_subject = (SEC_SUBJECT *)sec_sub;

	return sec_subject->name;
}

#define MAX_STATE_NUM  100
int sec_subject_create_statelist(void * sec_sub,char ** state_namelist)
{
	int ret;
	int i;
	int state_num;
	NAME2VALUE * new_name_list;
	SEC_SUBJECT * sec_subject;
	if(sec_sub==NULL)
		return -EINVAL;
	sec_subject = (SEC_SUBJECT *)sec_sub;
	if(state_namelist==NULL)
		return -EINVAL;
	// count the state's number in state_namelist
	for(i=0;state_namelist[i]!=NULL;i++)
	{
		if(i>=MAX_STATE_NUM)
			return -E2BIG;
	}

	// if this proc is the main proc, we should add the default namelist in it
	state_num=i;
	if(sec_subject_gettype(sec_sub)==PROC_TYPE_MAIN)
	{
		int default_state_num;
		for(i=0;default_state_list[i].name!=NULL;i++)
		{
			if(i>=MAX_STATE_NUM)
				return -E2BIG;
		}

		default_state_num=i;
		state_num+=default_state_num;
		if(state_num>=MAX_STATE_NUM)
			return -E2BIG;
	//      malloc space for state_namelist
		new_name_list=kmalloc(sizeof(NAME2VALUE)*(state_num+1),GFP_KERNEL);
		memset(new_name_list,0,sizeof(NAME2VALUE)*(state_num+1));

	// load the default state namelist
		for(i=0;i<default_state_num;i++)
		{
			new_name_list[i].name=dup_str(default_state_list[i].name,0);	
			new_name_list[i].value=default_state_list[i].value;	
		}
	// load the new namelist
		for(;i<state_num;i++)
		{
			new_name_list[i].name=dup_str(state_namelist[i-default_state_num],0);	
			new_name_list[i].value=0x1000+i-default_state_num;	
		}
	}
	else
	{
		new_name_list=kmalloc(sizeof(NAME2VALUE)*(state_num+1),GFP_KERNEL);
		memset(new_name_list,0,sizeof(NAME2VALUE)*(state_num+1));
	// load the new namelist
		for(;i<state_num;i++)
		{
			new_name_list[i].name=dup_str(state_namelist[i],0);	
			new_name_list[i].value=0x1000+i;	
		}
	}

	sec_subject->statename=new_name_list;
	return 0;
}

int sec_subject_register_statelist(void * sec_sub,NAME2VALUE * state_list)
{
	int ret;
	int i;
	int state_num;
	SEC_SUBJECT * sec_subject;
	if(sec_sub==NULL)
		return -EINVAL;
	sec_subject = (SEC_SUBJECT *)sec_sub;
	if(state_list==NULL)
		return -EINVAL;
	// count the state's number in state_namelist
	for(i=0;state_list[i].name!=NULL;i++)
	{
		if(i>=MAX_STATE_NUM)
			return -E2BIG;
	}

	// if this proc is the main proc, we should add the default namelist in it
	state_num=i;
	int default_state_num=0;
	if(sec_subject_gettype(sec_sub)==PROC_TYPE_MAIN)
	{
		for(i=0;default_state_list[i].name!=NULL;i++)
		{
			if(i>=MAX_STATE_NUM)
				return -E2BIG;
		}

		default_state_num=i;
	}
	// load the new namelist
	for(i=default_state_num;sec_subject->statename[i].name!=NULL;i++)
	{
		int j;
		for(j=0;j<state_num;j++)
		{
			if(!strcmp(sec_subject->statename[i].name,state_list[j].name))
			{
				sec_subject->statename[i].value=state_list[j].value;
				break;	
			}
		}
	}
	ret=struct_set_elem_var("fsm_state",sec_subject->statename,sec_subject->head_template);
	if(ret<0)
		return -EINVAL;	
	
	return 0;
}

#define MAX_FUNC_NUM  100
int sec_subject_create_funclist(void * sec_sub,char ** func_namelist)
{
	int ret;
	int i;
	int func_num;
	NAME2POINTER * new_func_list;
	SEC_SUBJECT * sec_subject;
	if(sec_sub==NULL)
		return -EINVAL;
	sec_subject = (SEC_SUBJECT *)sec_sub;
	if(func_namelist==NULL)
		return -EINVAL;
	// count the state's number in state_namelist
	for(i=0;func_namelist[i]!=NULL;i++)
	{
		if(i>=MAX_STATE_NUM)
			return -E2BIG;
	}

	func_num=i;
	new_func_list=kmalloc(sizeof(NAME2POINTER)*(func_num+1),GFP_KERNEL);
	memset(new_func_list,0,sizeof(NAME2POINTER)*(func_num+1));

	for(i=0;i<func_num;i++)
	{
		new_func_list[i].name=dup_str(func_namelist[i],0);	
		new_func_list[i].pointer=NULL;	
	}
	sec_subject->funcname=new_func_list;
	return 0;
}

int sec_subject_register_funclist(void * sec_sub,NAME2POINTER * func_list)
{
	int ret;
	int i;
	int func_num;
	SEC_SUBJECT * sec_subject;
	if(sec_sub==NULL)
		return -EINVAL;
	sec_subject = (SEC_SUBJECT *)sec_sub;
	if(func_list==NULL)
		return -EINVAL;
	// count the state's number in state_namelist
	for(i=0;func_list[i].name!=NULL;i++)
	{
		if(i>=MAX_STATE_NUM)
			return -E2BIG;
	}

	// if this proc is the main proc, we should add the default namelist in it
	func_num=i;
	// load the new namelist
	for(i=0;sec_subject->funcname[i].name!=NULL;i++)
	{
		int j;
		for(j=0;j<func_num;j++)
		{
			if(!strcmp(sec_subject->funcname[i].name,func_list[j].name))
			{
				sec_subject->funcname[i].pointer=func_list[j].pointer;
				break;	
			}
		}
	}
	return 0;
}

int sec_subject_getfunc(void * sec_sub,char * func_name, void ** func)
{
	int ret;
	int i;
	SEC_SUBJECT * sec_subject;
	if(sec_sub==NULL)
		return -EINVAL;
	sec_subject = (SEC_SUBJECT *)sec_sub;
	if(sec_subject->proc_state==SEC_PROC_CREATE) 
		return -EINVAL;
	*func=NULL;
	for(i=0;sec_subject->funcname[i].name!=NULL;i++)
	{
		if(!strcmp(sec_subject->funcname[i].name,func_name))
		{
			*func=sec_subject->funcname[i].pointer;
			break;	
		}
	}
	return 0;
}


int sec_subject_getstate(void * sec_sub)
{
	int ret;
	SEC_SUBJECT * sec_subject;
	if(sec_sub==NULL)
		return -EINVAL;
	sec_subject = (SEC_SUBJECT *)sec_sub;
	return sec_subject->fsm_state;
}

int sec_subject_setstate(void * sec_sub,int state)
{
	int ret;
	SEC_SUBJECT * sec_subject;
	if(sec_sub==NULL)
		return -EINVAL;
	sec_subject = (SEC_SUBJECT *)sec_sub;
	sec_subject->fsm_state=state;
	return 0;
}

int sec_subject_getpolicy(void * sec_sub,void ** deal_policy)
{
	int ret;
	SEC_SUBJECT * sec_subject;
	if(sec_sub==NULL)
		return -EINVAL;
	sec_subject = (SEC_SUBJECT *)sec_sub;
	*deal_policy=sec_subject->proc_policy;
	return 0;
}

int sec_subject_setpolicy(void * sec_sub,void * deal_policy)
{
	int ret;
	SEC_SUBJECT * sec_subject;
	if(sec_sub==NULL)
		return -EINVAL;
	sec_subject = (SEC_SUBJECT *)sec_sub;
	sec_subject->proc_policy=deal_policy;
	return 0;
}

int sec_subject_getstatestr(void * sec_sub,char ** statestr)
{
	int state;
	int ret;
	int i;
	*statestr=NULL;
	SEC_SUBJECT * sec_subject;
	if(sec_sub==NULL)
		return -EINVAL;
	sec_subject = (SEC_SUBJECT *)sec_sub;
	state=sec_subject_getstate(sec_sub);
	if(state<0)
		return state;
	for(i=0;sec_subject->statename[i].name!=NULL;i++)
	{
		if(sec_subject->statename[i].value==state)
		{
			*statestr=sec_subject->statename[i].name;
			break;
		}
	}
	return 0;
}

int sec_subject_teststate(void * sec_sub,char * statestr)
{
	int state;
	int ret;
	char * curr_statestr;
	ret=sec_subject_getstatestr(sec_sub,&curr_statestr);
	if(ret<0)
		return ret;
	if(curr_statestr==NULL)
		return -EINVAL;
	return !strcmp(curr_statestr,statestr);
}

int sec_subject_getcontext(void * sec_sub,void ** context)
{
	int ret;
	SEC_SUBJECT * sec_subject;
	if(sec_sub==NULL)
		return -EINVAL;
	sec_subject = (SEC_SUBJECT *)sec_sub;
	*context=sec_subject->context;
	return 0;
}

int _sec_subject_passpara(void * pointer)
{
	struct subject_para_struct
	{
		SEC_SUBJECT * sec_subject;
		void * para;
		int (*start)(void *,void *);
	};
	
	struct subject_para_struct * trans_pointer=pointer;
	
	if((trans_pointer==NULL) ||IS_ERR(trans_pointer))
	pthread_exit((void *)-EINVAL);
	trans_pointer->sec_subject->retval=trans_pointer->start(trans_pointer->sec_subject,trans_pointer->para);
	pthread_exit((void *)&(trans_pointer->sec_subject->retval));

}

int sec_subject_init(void * sec_sub,void * para)
{
	int ret;
	SEC_SUBJECT * sec_subject=(SEC_SUBJECT *)sec_sub;
	if(sec_sub==NULL)
	{
		return -EINVAL;
	}

	// judge if the sec_subject's state is right
	if(sec_subject->proc_state!=SEC_PROC_CREATE)
		return -EINVAL;
	if(sec_subject->init ==NULL)
	{
		ret=sec_object_setpointer(sec_subject->context,para);
		if(ret<0)
		{
			remove_sec_object(sec_subject->context);
			message_queue_destroy(&(sec_subject->send_queue));
			message_queue_destroy(&(sec_subject->recv_queue));
			pthread_mutex_destroy(&(sec_subject->mutex));
			pthread_cond_destroy(&(sec_subject->cond));
			kfree(sec_subject);
		}
		return ret;
	}
	ret=sec_subject->init(sec_sub,para);

	return ret;
}

int sec_subject_start(void * sec_sub,void * para)
{
	struct subject_para_struct
	{
		SEC_SUBJECT * sec_subject;
		void * para;
		int (*start)(void *,void *);
	};
	
	struct subject_para_struct * trans_pointer;

	int ret;
	
	SEC_SUBJECT * sec_subject=(SEC_SUBJECT *)sec_sub;
	if(sec_sub==NULL)
		return -EINVAL;
	if(sec_subject->start==NULL)
		return -EINVAL;

	trans_pointer=kmalloc(sizeof(struct subject_para_struct),GFP_KERNEL);
	if(trans_pointer==NULL)
	{
		kfree(trans_pointer);
		return -ENOMEM;
	}


	// judge if the sec_subject's state is right
	if((sec_subject->proc_state!=SEC_PROC_CREATE)
			&&(sec_subject->proc_state!=SEC_PROC_INIT))
		return -EINVAL;

	sec_subject = (SEC_SUBJECT *)sec_sub;
	trans_pointer->sec_subject=sec_sub;
	trans_pointer->para=para;
	trans_pointer->start=sec_subject->start;
	
	sec_subject->proc_state=SEC_PROC_START;

//	ret=pthread_create(&(sec_subject->proc_thread),&(sec_subject->thread_attr),start,trans_pointer);
	ret=pthread_create(&(sec_subject->proc_thread),NULL,_sec_subject_passpara,trans_pointer);
	return ret;

}

int sec_subject_join(void * sec_sub,int * retval)
{
	int ret;
	int * thread_return;
	SEC_SUBJECT * sec_subject;
	if(sec_sub==NULL)
	{
		return -EINVAL;
	}
	sec_subject = (SEC_SUBJECT *)sec_sub;
	ret=pthread_join(sec_subject->proc_thread,&thread_return);
	sec_subject->retval=*thread_return;
	*retval=*thread_return;
	sec_subject->proc_state=SEC_PROC_ZOMBIE;
	
	return ret;
}

int sec_subject_proc_getpara(void * arg,void ** sec_sub,void ** para)
{
	struct subject_para_struct
	{
		void * sec_subject;
		void * para;
	};
	
	if((arg==NULL) || IS_ERR(arg))
		return -EINVAL;
	printf("subject getpara!,arg=%x\n",arg);
	struct subject_para_struct * trans_pointer=(struct subject_para_struct * )arg;
	
	printf("sec_subject =%x\n",trans_pointer->sec_subject);
	if((trans_pointer->sec_subject==NULL)||IS_ERR(trans_pointer->sec_subject))
	{
		printf("sec subject get para err!\n");
		return -EINVAL;
	}

	*sec_sub=trans_pointer->sec_subject;
	*para=trans_pointer->para;
	kfree(trans_pointer);
	return 0;	
}


int sec_subject_sendmsg(void * sec_sub,void *msg)
{
	int ret;
	SEC_SUBJECT * sec_subject;
	if(sec_sub==NULL)
		return ;
	sec_subject = (SEC_SUBJECT *)sec_sub;

	return message_queue_putmsg(sec_subject->send_queue,msg);
}

int sec_subject_recvmsg(void * sec_sub,void **msg)
{
	int ret;
	SEC_SUBJECT * sec_subject;
	if(sec_sub==NULL)
		return ;
	sec_subject = (SEC_SUBJECT *)sec_sub;
	return message_queue_getmsg(sec_subject->recv_queue,msg);

}

int send_sec_subject_msg(void * sec_sub,void * msg)
{
	int ret;
	SEC_SUBJECT * sec_subject;
	if(sec_sub==NULL)
		return ;
	sec_subject = (SEC_SUBJECT *)sec_sub;
	return message_queue_putmsg(sec_subject->recv_queue,msg);

}

int recv_sec_subject_msg(void * sec_sub,void ** msg)
{
	int ret;
	SEC_SUBJECT * sec_subject;
	if(sec_sub==NULL)
		return ;
	sec_subject = (SEC_SUBJECT *)sec_sub;
	return message_queue_getmsg(sec_subject->send_queue,msg);
}

void sec_subject_destroy(void * sec_sub)
{
	int ret;
	SEC_SUBJECT * sec_subject;
	if(sec_sub==NULL)
		return ;
	sec_subject = (SEC_SUBJECT *)sec_sub;
	remove_sec_object(sec_subject->context);
	message_queue_destroy(sec_subject->send_queue);
	message_queue_destroy(sec_subject->recv_queue);
	pthread_mutex_destroy(&(sec_subject->mutex));
	pthread_cond_destroy(&(sec_subject->cond));
	kfree(sec_subject);
	return;
}
/*
int sec_subject_reset(void * sec_sub)
{
	int ret;
	void * share_data;
	void * struct_template;
	SEC_SUBJECT * sec_subject=(SEC_SUBJECT *)sec_sub;

	pthread_rwlock_wrlock(&(sec_subject->rwlock));
	sec_subject->state = -1;
	share_data=sec_subject->share_data;
	struct_template=sec_subject->struct_template;
	sec_subject->share_data=NULL;
	sec_subject->struct_template=NULL;
	sec_subject->pointer=NULL;
	pthread_rwlock_unlock(&(sec_subject->rwlock));

	if(share_data!=NULL)
		free_struct(share_data,struct_template);
	if(struct_template!=NULL)
		free_struct_template(sec_subject->struct_template);
	return 0;
}

int sec_subject_getstate(void * sec_sub)
{
	int state;
	SEC_SUBJECT * sec_subject=(SEC_SUBJECT *)sec_sub;
	if(sec_subject==NULL)
		return -1;
	pthread_rwlock_rdlock(&(sec_subject->rwlock));
	state=sec_subject->state;
	pthread_rwlock_unlock(&(sec_subject->rwlock));
	return state;
}

int sec_subject_setstate(void * sec_sub,int state)
{
	SEC_SUBJECT * sec_subject=(SEC_SUBJECT *)sec_sub;
	if(sec_subject==NULL)
		return -1;
	pthread_rwlock_wrlock(&(sec_subject->rwlock));
	sec_subject->state=state;
	pthread_rwlock_unlock(&(sec_subject->rwlock));
	return state;
}
void * sec_subject_getpointer(void * sec_sub)
{
	void * pointer;
	SEC_SUBJECT * sec_subject=(SEC_SUBJECT *)sec_sub;
	if(sec_subject==NULL)
		return -1;
	pthread_rwlock_rdlock(&(sec_subject->rwlock));
	pointer=sec_subject->pointer;
	pthread_rwlock_unlock(&(sec_subject->rwlock));
	return pointer;
}
int sec_subject_setpointer(void * sec_sub,void * pointer)
{
	SEC_SUBJECT * sec_subject=(SEC_SUBJECT *)sec_sub;
	if(sec_subject==NULL)
		return -1;
	pthread_rwlock_wrlock(&(sec_subject->rwlock));
	sec_subject->pointer=pointer;
	pthread_rwlock_unlock(&(sec_subject->rwlock));
	return 0;
}
int sec_subject_getvalue(void * sec_sub,char * valuename,void * value)
{
	int ret;
	SEC_SUBJECT * sec_subject=(SEC_SUBJECT *)sec_sub;
	if(sec_subject==NULL)
		return -EINVAL;
	
	pthread_rwlock_wrlock(&(sec_subject->rwlock));
	ret=struct_read_elem(valuename,sec_subject->share_data,value,sec_subject->struct_template);
	pthread_rwlock_unlock(&(sec_subject->rwlock));
	return ret;
}
int sec_subject_setvalue(void * sec_sub,char * valuename,void * value)
{
	int ret;
	SEC_SUBJECT * sec_subject=(SEC_SUBJECT *)sec_sub;
	if(sec_subject==NULL)
		return -EINVAL;
	pthread_rwlock_wrlock(&(sec_subject->rwlock));
	ret=struct_write_elem(valuename,sec_subject->share_data,value,sec_subject->struct_template);
	pthread_rwlock_unlock(&(sec_subject->rwlock));
	return ret;
}
int sec_subject_destroy(void * sec_sub)
{
	int ret;
	SEC_SUBJECT * sec_subject=(SEC_SUBJECT *)sec_sub;
	sec_subject_reset(sec_subject);
	ret=pthread_rwlock_destroy(&(sec_subject->rwlock));
	if(ret<0)
		return ret;
	kfree(sec_subject)t;
	sec_subject=NULL;
	return 0;
}
*/
