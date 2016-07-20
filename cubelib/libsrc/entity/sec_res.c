#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "../include/data_type.h"
#include "../include/kernel_comp.h"
#include "../include/list.h"
#include "../include/attrlist.h"
#include "../include/struct_deal.h"
#include "../include/extern_defno.h"
#include "../include/extern_struct.h"
#include "../include/logic_baselib.h"
#include "../include/sec_entity.h"

typedef struct tag_secure_respool
{
	char uuid[DIGEST_SIZE*2];
	char name[DIGEST_SIZE*2];
	pthread_rwlock_t rwlock;
	int state;
	int res_num;
	int free_num;
	Record_List occupy_res;
	Record_List free_res;
} SEC_RESPOOL;

typedef struct tag_secure_resource
{
	int  res_no;
	char uuid[DIGEST_SIZE*2];
	pthread_rwlock_t rwlock;
	int state;
	void * pointer;
	void * struct_template;
	void * describe;
} SEC_RESOURCE;

struct secure_respool_list
{
	int state;
	pthread_rwlock_t rwlock;
	Record_List head;
	struct list_head * curr;
}; 

static struct secure_respool_list * sec_respool_list;

enum sec_respool_list_state
{
	SEC_RESPOOL_LIST_INIT,
	SEC_RESPOOL_LIST_ERR,
};

int sec_respool_list_init()
{
	int ret;
	sec_respool_list=malloc(sizeof(struct secure_respool_list));
	if(sec_respool_list==NULL)
		return -ENOMEM;
	INIT_LIST_HEAD(&(sec_respool_list->head.list));
	sec_respool_list->head.record=NULL;
	sec_respool_list->curr=&(sec_respool_list->head.list);
	ret=pthread_rwlock_init(&(sec_respool_list->rwlock),NULL);
	if(ret<0)
		return -EINVAL;
	return 0;
}

void * find_sec_respool(char * uuid)
{
	struct list_head * curr_head;
	Record_List * record_elem;
	Record_List * record_list;
	record_list=&(sec_respool_list->head);
	int ret;

	pthread_rwlock_rdlock(&(sec_respool_list->rwlock));
	curr_head = find_elem_with_tag(record_list,
		entity_comp_uuid,uuid);
	pthread_rwlock_unlock(&(sec_respool_list->rwlock));
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

void * get_first_sec_respool()
{
	Record_List * recordhead;
	Record_List * newrecord;
	struct list_head * curr_head;

	pthread_rwlock_rdlock(&(sec_respool_list->rwlock));
	recordhead = &(sec_respool_list->head);
	if(recordhead==NULL)
	{
		pthread_rwlock_unlock(&(sec_respool_list->rwlock));
		return NULL;
	}
	curr_head = recordhead->list.next;
	sec_respool_list->curr = curr_head;
	newrecord = list_entry(curr_head,Record_List,list);
	pthread_rwlock_unlock(&(sec_respool_list->rwlock));
	return newrecord->record;
}

void * get_next_sec_respool()
{
	Record_List * recordhead;
	Record_List * newrecord;
	struct list_head * curr_head;

	recordhead = &(sec_respool_list->head);
	if(recordhead==NULL)
	{
		return NULL;
	}
	pthread_rwlock_rdlock(&(sec_respool_list->rwlock));
	curr_head = sec_respool_list->curr->next;
	if(curr_head==recordhead)
	{
		pthread_rwlock_unlock(&(sec_respool_list->rwlock));
		return NULL;
	}
	sec_respool_list->curr = curr_head;
	newrecord = list_entry(curr_head,Record_List,list);
	pthread_rwlock_unlock(&(sec_respool_list->rwlock));
	return newrecord->record;
}

int add_sec_respool(void * sec_respool)
{
	Record_List * recordhead;
	Record_List * newrecord;

	recordhead = &(sec_respool_list->head);
	if(recordhead==NULL)
		return -ENOMEM;

	newrecord = kmalloc(sizeof(Record_List),GFP_KERNEL);
	if(newrecord==NULL)
		return -ENOMEM;
	INIT_LIST_HEAD(&(newrecord->list));
	newrecord->record=sec_respool;
	pthread_rwlock_wrlock(&(sec_respool_list->rwlock));
	list_add_tail(&(newrecord->list),recordhead);
	pthread_rwlock_unlock(&(sec_respool_list->rwlock));
	return 0;
}	

void * remove_sec_respool(char * uuid)
{
	Record_List * recordhead;
	Record_List * record_elem;
	struct list_head * curr_head;
	void * record;

	recordhead = &(sec_respool_list->head);
	if(recordhead==NULL)
		return NULL;

	pthread_rwlock_wrlock(&(sec_respool_list->rwlock));

	curr_head=find_elem_with_tag(recordhead,entity_comp_uuid,uuid);
	if(curr_head==NULL)
	{
		pthread_rwlock_unlock(&(sec_respool_list->rwlock));
		return NULL;
	}
	record_elem=list_entry(curr_head,Record_List,list);
	list_del(curr_head);
	pthread_rwlock_unlock(&(sec_respool_list->rwlock));
	record=record_elem->record;
	kfree(record_elem);	
	return record;
}	

void * sec_respool_init(char * uuid)
{
	int ret;
	SEC_RESPOOL * sec_respool;

	sec_respool=kmalloc(sizeof(SEC_RESPOOL),GFP_KERNEL);
	if(sec_respool==NULL)
		return NULL;
	memset(sec_respool,0,sizeof(SEC_RESPOOL));

	if(uuid==NULL)
		return NULL;
	strncpy(sec_respool->uuid,uuid,DIGEST_SIZE*2);

	INIT_LIST_HEAD(&(sec_respool->occupy_res.list));
	INIT_LIST_HEAD(&(sec_respool->free_res.list));
	ret=pthread_rwlock_init(&(sec_respool->rwlock),NULL);
	if(ret<0)
	{
		kfree(sec_respool);
		return -EINVAL;
	}
	return sec_respool;
}

void * sec_resource_init(char * uuid,struct struct_elem_attr *  share_data_desc)
{
	int ret;
	SEC_RESOURCE * sec_resource;

	sec_resource=kmalloc(sizeof(SEC_RESOURCE),GFP_KERNEL);
	if(sec_resource==NULL)
		return NULL;
	memset(sec_resource,0,sizeof(SEC_RESOURCE));

	if(uuid==NULL)
		return NULL;
	strncpy(sec_resource->uuid,uuid,DIGEST_SIZE*2);

	if(share_data_desc!=NULL)
	{
		sec_resource->struct_template=create_struct_template(share_data_desc);
		if((sec_resource->struct_template == NULL)
			&& IS_ERR(sec_resource->struct_template))
			return NULL;
		ret=alloc_struct(&(sec_resource->describe),sec_resource->struct_template);	
		if(ret<0)
		{
			kfree(sec_resource);
			return NULL;
		}
	}
	ret=pthread_rwlock_init(&(sec_resource->rwlock),NULL);
	if(ret<0)
	{
		free_struct(sec_resource->describe,sec_resource->struct_template);
		free_struct_template(sec_resource->struct_template);
		kfree(sec_resource);
		return -EINVAL;
	}
	return sec_resource;
}

int sec_respool_addres(void * respool,void * res)
{
	Record_List * recordhead;
	Record_List * newrecord;
	SEC_RESPOOL * sec_respool=(SEC_RESPOOL * )respool;
	SEC_RESOURCE * sec_res=(SEC_RESOURCE * )res;

	if(respool==NULL)
		return -EINVAL;
	if(res==NULL)
		return -EINVAL;

	recordhead = &(sec_respool->free_res.list);
	if(recordhead==NULL)
		return -ENOMEM;


	newrecord = kmalloc(sizeof(Record_List),GFP_KERNEL);
	if(newrecord==NULL)
		return -ENOMEM;
	INIT_LIST_HEAD(&(newrecord->list));
	newrecord->record=res;
	pthread_rwlock_wrlock(&(sec_respool->rwlock));
	list_add_tail(&(newrecord->list),recordhead);
	sec_respool->res_num++;
	sec_respool->free_num++;
	pthread_rwlock_unlock(&(sec_respool->rwlock));
	pthread_rwlock_wrlock(&(sec_res->rwlock));
	sec_res->state=SEC_RES_FREE;
	pthread_rwlock_unlock(&(sec_res->rwlock));
	return 0;

}


int sec_respool_getres(void * respool,void ** res)
{
	struct list_head * recordhead;
	struct list_head * next;
	Record_List * newrecord;
	SEC_RESPOOL * sec_respool=(SEC_RESPOOL * )respool;
	SEC_RESOURCE * sec_res;
	int ret;

	if(respool==NULL)
		return -EINVAL;

	recordhead = &(sec_respool->free_res.list);
	if(recordhead==NULL)
		return -ENOMEM;

	*res=NULL;

	pthread_rwlock_wrlock(&(sec_respool->rwlock));
	next=recordhead->next;
	if(next!=recordhead)
	{
		list_del(next);
		sec_respool->free_num--;
		newrecord=(Record_List *)next;
		*res=newrecord->record;
		recordhead = &(sec_respool->occupy_res.list);
		list_add_tail(next,recordhead);
		sec_res=*res;
		sec_res->state=SEC_RES_OCCUPY;
	}
	pthread_rwlock_unlock(&(sec_respool->rwlock));

	if (*res!=NULL)
		return 1;
	return 0;	
}


int sec_respool_freeres(void * respool,void * res)
{
	struct list_head * recordhead;
	struct list_head * next;
	Record_List * newrecord;
	SEC_RESPOOL * sec_respool=(SEC_RESPOOL * )respool;
	SEC_RESOURCE * sec_res;
	int ret;

	if(respool==NULL)
		return -EINVAL;

	recordhead = &(sec_respool->occupy_res.list);
	if(recordhead==NULL)
		return -ENOMEM;

	pthread_rwlock_wrlock(&(sec_respool->rwlock));
	next=recordhead->next;
	while(next!=recordhead)
	{
		newrecord=(Record_List *)next;
		if(newrecord->record==res)
		{
			list_del(next);
			sec_respool->free_num++;
			recordhead = &(sec_respool->free_res.list);
			list_add_tail(next,recordhead);
			sec_res=res;
			sec_res->state=SEC_RES_FREE;
			break;
		}
		next=next->next;
	}
	pthread_rwlock_unlock(&(sec_respool->rwlock));
	return 0;	
}

int sec_respool_reset(void * respool)
{
	int ret;
	void * share_data;
	void * struct_template;
	SEC_RESPOOL * sec_respool=(SEC_RESPOOL *)respool;

	pthread_rwlock_wrlock(&(sec_respool->rwlock));
	sec_respool->state = -1;
	sec_respool->res_num=0;
	sec_respool->free_num=0;
	INIT_LIST_HEAD(&(sec_respool->occupy_res.list));
	INIT_LIST_HEAD(&(sec_respool->free_res.list));

	pthread_rwlock_unlock(&(sec_respool->rwlock));
	return 0;
}

int sec_respool_getstate(void * sec_obj)
{
	int state;
	SEC_RESPOOL * sec_respool=(SEC_RESPOOL *)sec_obj;
	if(sec_respool==NULL)
		return -1;
	pthread_rwlock_rdlock(&(sec_respool->rwlock));
	state=sec_respool->state;
	pthread_rwlock_unlock(&(sec_respool->rwlock));
	return state;
}

int sec_respool_setstate(void * sec_obj,int state)
{
	SEC_RESPOOL * sec_respool=(SEC_RESPOOL *)sec_obj;
	if(sec_respool==NULL)
		return -1;
	pthread_rwlock_wrlock(&(sec_respool->rwlock));
	sec_respool->state=state;
	pthread_rwlock_unlock(&(sec_respool->rwlock));
	return state;
}
void * sec_resource_getpointer(void * sec_res)
{
	void * pointer;
	SEC_RESOURCE * sec_resource=(SEC_RESOURCE *)sec_res;
	if(sec_resource==NULL)
		return -1;
	pthread_rwlock_rdlock(&(sec_resource->rwlock));
	pointer=sec_resource->pointer;
	pthread_rwlock_unlock(&(sec_resource->rwlock));
	return pointer;
}
int sec_resource_setpointer(void * sec_res,void * pointer)
{
	SEC_RESOURCE * sec_resource=(SEC_RESOURCE *)sec_res;
	if(sec_resource==NULL)
		return -1;
	pthread_rwlock_wrlock(&(sec_resource->rwlock));
	sec_resource->pointer=pointer;
	pthread_rwlock_unlock(&(sec_resource->rwlock));
	return 0;
}
int sec_resource_getvalue(void * sec_res,char * valuename,void * value)
{
	int ret;
	SEC_RESOURCE * sec_resource=(SEC_RESOURCE *)sec_res;
	if(sec_resource==NULL)
		return -EINVAL;
	
	pthread_rwlock_rdlock(&(sec_resource->rwlock));
	ret=struct_read_elem(valuename,sec_resource->describe,value,sec_resource->struct_template);
	pthread_rwlock_unlock(&(sec_resource->rwlock));
	return ret;
}
int sec_resource_setvalue(void * sec_res,char * valuename,void * value)
{
	int ret;
	SEC_RESOURCE * sec_resource=(SEC_RESOURCE *)sec_res;
	if(sec_resource==NULL)
		return -EINVAL;
	pthread_rwlock_wrlock(&(sec_resource->rwlock));
	ret=struct_write_elem(valuename,sec_resource->describe,value,sec_resource->struct_template);
	pthread_rwlock_unlock(&(sec_resource->rwlock));
	return ret;
}
int sec_resource_destroy(void * sec_res)
{
	int ret;
	SEC_RESOURCE * sec_resource=(SEC_RESPOOL *)sec_res;
	ret=pthread_rwlock_destroy(&(sec_resource->rwlock));
	if(ret<0)
		return ret;
	kfree(sec_resource);
	sec_resource=NULL;
	return 0;
}

