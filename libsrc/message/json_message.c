
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include  "../include/kernel_comp.h"
#include "../include/list.h"
#include "../include/attrlist.h"
#include "../include/data_type.h"
#include "../include/struct_deal.h"
#include "../include/message_struct.h"
#include "../include/vmlist.h"
#include "../include/vtpm_struct.h"
#include "../include/vm_policy.h"
#include "../include/valuename.h"
#include "../include/message_struct_desc.h" 
#include "../include/vm_policy_desc.h"
#include "../include/vmlist_desc.h"
#include "../include/vtpm_desc.h"

#include "message_box.h"

int message_2_json(void * message,char * json_str)
{
    struct message_box * msg_box;
    int ret;
    MESSAGE_HEAD * msg_head;
    BYTE * data;
    BYTE buffer[1024];
    int i,j;
    int record_size,expand_size;
    int head_size;
    int no;
    const int bufsize=4096;
    int offset=0;
    int elem_offset=0;
    int seg_offset=0;
	
    MESSAGE_EXPAND * expand;
    void * expand_template;

    struct struct_elem_attr * record_desc;
    msg_box=(struct message_box *)message;
    msg_head=get_message_head(msg_box);


    if(message==NULL)
        return -EINVAL;

    strcpy(json_str,"{\"HEAD\":");
    offset=strlen(json_str);
    seg_offset=struct_2_json(msg_head,json_str,msg_box->head_template,&offset);



    json_str[offset++]=',';
    strcpy(buffer,"\"RECORD\":");
    strcpy(json_str+offset,buffer);
    offset+=strlen(buffer);
   
    
   if((message_get_flag(message) & MSG_FLAG_CRYPT)
	||(msg_box->record_template==NULL))
   {
	if(msg_box->blob==NULL)
	{
    		strcpy(buffer,"{\"EMPTY\":\"\"");
    		strcpy(json_str+offset,buffer);
    		offset+=strlen(buffer);
    		json_str[offset++]='}';
	}
	else
	{	
    		strcpy(buffer,"{\"BIN_FORMAT\":");
    		strcpy(json_str+offset,buffer);
    		offset+=strlen(buffer);
    		json_str[offset++]='\"';
		seg_offset=bin_to_radix64(json_str+offset,msg_head->record_size,msg_box->blob);
		offset+=seg_offset;	
    		json_str[offset++]='\"';
    		json_str[offset++]='}';
	}
   }
    else 
    {   
    	json_str[offset++]='[';
    	for(i=0;i<msg_head->record_num;i++)
    	{
        	seg_offset=struct_2_json(msg_box->precord[i],json_str,msg_box->record_template,&offset);
		if(i<msg_head->record_num-1)
        		json_str[offset++]=',';
    	}
    	json_str[offset++]=']';
    }

    json_str[offset++]=',';

    strcpy(buffer,"\"EXPAND\":");
    strcpy(json_str+offset,buffer);
    offset+=strlen(buffer);
    json_str[offset++]='[';
    for(i=0;i<msg_head->expand_num;i++)
    {	
    	expand=(MESSAGE_EXPAND *)msg_box->pexpand[i];
	if(expand!=NULL)
	{
  	 	expand_template=load_record_template(expand->tag);
   		if(expand_template!=NULL)
		{
        		seg_offset=struct_2_json(expand,json_str,expand_template,&offset);
			if(i<msg_head->expand_num-1)
        			json_str[offset++]=',';
		}	
	}
	else
	{
    		expand=(MESSAGE_EXPAND *)msg_box->expand[i];
    		sprintf(buffer,"{ \"data_size\":%d,\"tag\":\"%4.4s\",",expand->data_size,expand->tag);
		strcat(	buffer,"\"BIN_FORMAT\":");
    		strcpy(json_str+offset,buffer);
    		offset+=strlen(buffer);
    		json_str[offset++]='\"';
		seg_offset=bin_to_radix64(json_str+offset,expand->data_size-sizeof(MESSAGE_EXPAND),expand->data);
		offset+=seg_offset;	
    		json_str[offset++]='\"';
    		json_str[offset++]='}';

	}
    }
    json_str[offset++]=']';
    json_str[offset++]='}';
    return offset;
}

int json_2_message(char * json_str,void ** message)
{

    void * root_node;
    void * head_node;
    void * tag_node;
    void * record_node;
    void * curr_record;
    void * expand_node;
    void * curr_expand;

    void * record_value;
    void * expand_value;

    struct message_box * msg_box;
    MESSAGE_HEAD * msg_head;
    int record_no;
    int expand_no;
    void * precord;
    void * pexpand;
    int i;
    int ret;

    char type[10];

    int offset;
    offset=json_solve_str(&root_node,json_str);
    if(offset<0)
        return offset;

    // get json node's head
    head_node=find_json_elem("HEAD",root_node);
    if(head_node==NULL)
        return -EINVAL;
    tag_node=find_json_elem("tag",head_node);
    if(tag_node==NULL)
        return -EINVAL;
    ret=get_json_value_from_node(tag_node,type,10);
    if(ret!=4)
        return -EINVAL;
    msg_box=message_init(type,0x00010001);
    msg_head=get_message_head(msg_box);
    json_2_struct(head_node,msg_head,msg_box->head_template);


    // get json node's record
    // init message box
    ret=message_record_init(msg_box);
    if(ret<0)
        return ret;

    record_node=find_json_elem("RECORD",root_node);
    if(record_node==NULL)
        return -EINVAL;

    curr_record=get_first_json_child(record_node);
    if(curr_record==NULL)
         return -EINVAL;
    char node_name[DIGEST_SIZE*2];
    ret=get_json_name_from_node(curr_record,node_name);
    if(!strcmp(node_name,"BIN_FORMAT"))
    {
	BYTE * radix64_string;
	radix64_string=malloc(4096);
	if(radix64_string==NULL)
		return -ENOMEM;
	ret=get_json_value_from_node(curr_record,radix64_string,4096);
	if(ret<0)
		return -EINVAL;
	int radix64_len=strnlen(radix64_string,4096);
	msg_head->record_size=radix_to_bin_len(radix64_len);
	msg_box->blob=malloc(msg_head->record_size);
	if(msg_box->blob==NULL)
		return -ENOMEM;
	ret=radix64_to_bin(msg_box->blob,radix64_len,radix64_string);
   }
    else
   {
    	for(i=0;i<msg_head->record_num;i++)
    	{
        	if(curr_record==NULL)
            		return -EINVAL;
        	ret=alloc_struct(&precord,msg_box->record_template);
        	if(ret<=0)
            		return -EINVAL;
       		json_2_struct(curr_record,precord,msg_box->record_template);
        	message_add_record(msg_box,precord);
        	curr_record=get_next_json_child(record_node);
	}
    }

    // get json_node's expand
    expand_node=find_json_elem("EXPAND",root_node); 
    expand_no=msg_head->expand_num;
    msg_head->expand_num=0;
    if(expand_node!=NULL)
    {
	char buf[20];
	curr_expand=get_first_json_child(expand_node);
   	for(i=0;i<expand_no;i++)
    	{
        	if(curr_expand==NULL)
            		return -EINVAL;
		void * expand_tag=find_json_elem("tag",curr_expand);
		if(expand_tag==NULL)
			return -EINVAL;
		if(json_get_type(expand_tag)!=JSON_ELEM_STRING)
			return -EINVAL;
		ret=get_json_value_from_node(expand_tag,buf,5);
		if(strnlen(buf,5)!=4)
			return -EINVAL;
		void * curr_template=load_record_template(buf);
		if(curr_template==NULL)
			return -EINVAL;
		
        	ret=alloc_struct(&pexpand,curr_template);
        	if(ret<=0)
            		return -EINVAL;
        	json_2_struct(curr_expand,pexpand,curr_template);
        	message_add_expand(msg_box,pexpand);
        	curr_expand=get_next_json_child(expand_node);
	}
    }


    *message=msg_box;
    msg_box->box_state = MSG_BOX_RECOVER;
    return offset;
}
