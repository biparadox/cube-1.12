#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#ifndef WINDOWS_COMP
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#else
#include <windows.h>
#include <winsock.h>
#include <winsock2.h>
#endif
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
#include "../include/vm_policy.h"
//#include "../include/vm_policy_desc.h"
#include "../include/vmlist.h"
//#include "../include/vmlist_desc.h"
#include "../include/vtpm_struct.h"
//#include "../include/vtpm_desc.h"
#include "../include/openstack_trust_lib.h"

typedef struct proc_secure_object
{
	char uuid[DIGEST_SIZE*2];
	pthread_rwlock_t rwlock;
	int state;
	int count;
	void * pointer;
	void * struct_template;
	void * share_data;
} SEC_OBJECT;

struct secure_object_list
{
	int state;
	pthread_rwlock_t rwlock;
	Record_List head;
	struct list_head * curr;
}; 

static struct secure_object_list * sec_object_list;

enum sec_object_list_state
{
	SEC_OBJECT_LIST_INIT,
	SEC_OBJECT_LIST_ERR,
};

int sec_object_list_init()
{
	int ret;
	sec_object_list=malloc(sizeof(struct secure_object_list));
	if(sec_object_list==NULL)
		return -ENOMEM;
	INIT_LIST_HEAD(&(sec_object_list->head.list));
	sec_object_list->head.record=NULL;
	sec_object_list->curr=&(sec_object_list->head.list);
	ret=pthread_rwlock_init(&(sec_object_list->rwlock),NULL);
	if(ret<0)
		return -EINVAL;
	return 0;
}

void * find_sec_object(char * uuid)
{
	struct list_head * curr_head;
	Record_List * record_elem;
	Record_List * record_list;
	record_list=&(sec_object_list->head);
	int ret;

	pthread_rwlock_rdlock(&(sec_object_list->rwlock));
	curr_head = find_elem_with_tag(record_list,
		entity_comp_uuid,uuid);
	pthread_rwlock_unlock(&(sec_object_list->rwlock));
	if(curr_head == NULL)
	{
		return NULL;
	}
	if(IS_ERR(curr_head))
	{
		return curr_head;
	}
	record_elem=list_entry(curr_head,Record_List,list);
	return record_elem->record;	
}

void * get_first_sec_object()
{
	Record_List * recordhead;
	Record_List * newrecord;
	struct list_head * curr_head;

	pthread_rwlock_rdlock(&(sec_object_list->rwlock));
	recordhead = &(sec_object_list->head);
	if(recordhead==NULL)
	{
		pthread_rwlock_unlock(&(sec_object_list->rwlock));
		return NULL;
	}
	curr_head = recordhead->list.next;
	sec_object_list->curr = curr_head;
	newrecord = list_entry(curr_head,Record_List,list);
	pthread_rwlock_unlock(&(sec_object_list->rwlock));
	return newrecord->record;
}

void * get_next_sec_object()
{
	Record_List * recordhead;
	Record_List * newrecord;
	struct list_head * curr_head;

	recordhead = &(sec_object_list->head);
	if(recordhead==NULL)
	{
		return NULL;
	}
	pthread_rwlock_rdlock(&(sec_object_list->rwlock));
	curr_head = sec_object_list->curr->next;
	if(curr_head==recordhead)
	{
		pthread_rwlock_unlock(&(sec_object_list->rwlock));
		return NULL;
	}
	sec_object_list->curr = curr_head;
	newrecord = list_entry(curr_head,Record_List,list);
	pthread_rwlock_unlock(&(sec_object_list->rwlock));
	return newrecord->record;
}

int add_sec_object(void * sec_object)
{
	Record_List * recordhead;
	Record_List * newrecord;

	recordhead = &(sec_object_list->head);
	if(recordhead==NULL)
		return -ENOMEM;

	newrecord = kmalloc(sizeof(Record_List),GFP_KERNEL);
	if(newrecord==NULL)
		return -ENOMEM;
	INIT_LIST_HEAD(&(newrecord->list));
	newrecord->record=sec_object;
	pthread_rwlock_wrlock(&(sec_object_list->rwlock));
	list_add_tail(&(newrecord->list),recordhead);
	pthread_rwlock_unlock(&(sec_object_list->rwlock));
	return 0;
}	

void * remove_sec_object(char * uuid)
{
	Record_List * recordhead;
	Record_List * record_elem;
	struct list_head * curr_head;
	void * record;

	recordhead = &(sec_object_list->head);
	if(recordhead==NULL)
		return NULL;

	pthread_rwlock_wrlock(&(sec_object_list->rwlock));

	curr_head=find_elem_with_tag(recordhead,entity_comp_uuid,uuid);
	if(curr_head==NULL)
	{
		pthread_rwlock_unlock(&(sec_object_list->rwlock));
		return NULL;
	}
	record_elem=list_entry(curr_head,Record_List,list);
	list_del(curr_head);
	record=record_elem->record;
	kfree(record_elem);	
	return record;
}	

void * sec_object_init(char * uuid,struct struct_elem_attr *  share_data_desc)
{
	int ret;
	SEC_OBJECT * sec_object;

	sec_object=kmalloc(sizeof(SEC_OBJECT),GFP_KERNEL);
	if(sec_object==NULL)
		return NULL;
	memset(sec_object,0,sizeof(SEC_OBJECT));

	if(uuid==NULL)
		return NULL;
	strncpy(sec_object->uuid,uuid,DIGEST_SIZE*2);

	if(share_data_desc!=NULL)
	{
		sec_object->struct_template=create_struct_template(share_data_desc);
		if((sec_object->struct_template == NULL)
			&& IS_ERR(sec_object->struct_template))
			return NULL;
		ret=alloc_struct(&(sec_object->share_data),sec_object->struct_template);	
		if(ret<0)
		{
			kfree(sec_object);
			return NULL;
		}
	}
	ret=pthread_rwlock_init(&(sec_object->rwlock),NULL);
	if(ret<0)
	{
		free_struct(sec_object->share_data,sec_object->struct_template);
		return -EINVAL;
	}
	return sec_object;
}

int sec_object_reset(void * sec_obj)
{
	int ret;
	void * share_data;
	void * struct_template;
	SEC_OBJECT * sec_object=(SEC_OBJECT *)sec_obj;

	pthread_rwlock_wrlock(&(sec_object->rwlock));
	sec_object->state = -1;
	share_data=sec_object->share_data;
	struct_template=sec_object->struct_template;
	sec_object->share_data=NULL;
	sec_object->struct_template=NULL;
	sec_object->pointer=NULL;
	pthread_rwlock_unlock(&(sec_object->rwlock));

	if(share_data!=NULL)
		free_struct(share_data,struct_template);
	if(struct_template!=NULL)
		free_struct_template(sec_object->struct_template);
	return 0;
}

int sec_object_getstate(void * sec_obj)
{
	int state;
	SEC_OBJECT * sec_object=(SEC_OBJECT *)sec_obj;
	if(sec_object==NULL)
		return -1;
	pthread_rwlock_rdlock(&(sec_object->rwlock));
	state=sec_object->state;
	pthread_rwlock_unlock(&(sec_object->rwlock));
	return state;
}

int sec_object_setstate(void * sec_obj,int state)
{
	SEC_OBJECT * sec_object=(SEC_OBJECT *)sec_obj;
	if(sec_object==NULL)
		return -1;
	pthread_rwlock_wrlock(&(sec_object->rwlock));
	sec_object->state=state;
	pthread_rwlock_unlock(&(sec_object->rwlock));
	return state;
}
void * sec_object_getpointer(void * sec_obj)
{
	void * pointer;
	SEC_OBJECT * sec_object=(SEC_OBJECT *)sec_obj;
	if(sec_object==NULL)
		return -1;
	pthread_rwlock_rdlock(&(sec_object->rwlock));
	pointer=sec_object->pointer;
	pthread_rwlock_unlock(&(sec_object->rwlock));
	return pointer;
}
int sec_object_setpointer(void * sec_obj,void * pointer)
{
	SEC_OBJECT * sec_object=(SEC_OBJECT *)sec_obj;
	if(sec_object==NULL)
		return -1;
	pthread_rwlock_wrlock(&(sec_object->rwlock));
	sec_object->pointer=pointer;
	pthread_rwlock_unlock(&(sec_object->rwlock));
	return 0;
}
int sec_object_getvalue(void * sec_obj,char * valuename,void * value)
{
	int ret;
	SEC_OBJECT * sec_object=(SEC_OBJECT *)sec_obj;
	if(sec_object==NULL)
		return -EINVAL;
	
	pthread_rwlock_wrlock(&(sec_object->rwlock));
	ret=struct_read_elem(valuename,sec_object->share_data,value,sec_object->struct_template);
	pthread_rwlock_unlock(&(sec_object->rwlock));
	return ret;
}
int sec_object_setvalue(void * sec_obj,char * valuename,void * value)
{
	int ret;
	SEC_OBJECT * sec_object=(SEC_OBJECT *)sec_obj;
	if(sec_object==NULL)
		return -EINVAL;
	pthread_rwlock_wrlock(&(sec_object->rwlock));
	ret=struct_write_elem(valuename,sec_object->share_data,value,sec_object->struct_template);
	pthread_rwlock_unlock(&(sec_object->rwlock));
	return ret;
}
int sec_object_destroy(void * sec_obj)
{
	int ret;
	SEC_OBJECT * sec_object=(SEC_OBJECT *)sec_obj;
	sec_object_reset(sec_object);
	ret=pthread_rwlock_destroy(&(sec_object->rwlock));
	if(ret<0)
		return ret;
	kfree(sec_object);
	sec_object=NULL;
	return 0;
}

