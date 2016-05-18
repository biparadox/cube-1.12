#ifdef KERNEL_MODE

#include <linux/string.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/errno.h>

#else

#include<stdlib.h>
#include<string.h>
#include<errno.h>
#include<time.h>
#include "../include/kernel_comp.h"
#include "../include/list.h"
#endif

#include "../include/data_type.h"
#include "../include/struct_deal.h"
#include "../include/attrlist.h"
//#include "cipher.h"
#include "radix64.h"
#include "struct_internal.h"
#define DIGEST_SIZE 32


enum json_solve_state
{
    JSON_SOLVE_INIT,
    JSON_SOLVE_PROCESS,
    JSON_SOLVE_FINISH,
    JSON_VALUE_TRANS
};

enum solve_state
{
    SOLVE_INIT,
    SOLVE_ARRAY,
    SOLVE_MAP,
    SOLVE_NAME,
    SOLVE_VALUE,
    SOLVE_UPGRADE,
    SOLVE_FINISH
};



typedef struct json_value_struct
{
     int value_type;
     char * value_str;
     void * value;
}JSON_VALUE;

static inline int IsValueEnd(char c)
{
    if((c==' ')||(c==',')||(c=='\0')||(c=='}')||(c==']'))
    {
        return 1;
    }
    return 0;
}
static inline int IsSplitChar(char c)
{
    if((c==',')||(c==' ')||(c=='\r')||(c=='\n')||(c=='\t'))
    {
        return 1;
    }
    return 0;
}
typedef struct json_elem_node
{
    int elem_type;            //  this json elem's type, it can be
                             //  NUM,STRING,BOOL,MAP,ARRAY or NULL

    char name[DIGEST_SIZE*2]; // this json elem's name,
                              // if this json elem is the root elem,
                              //  its name is "__ROOT__"
    int solve_state;                // this json elem's state, it should
                              // be JSON_SOLVE_INIT,JSON_SOLVE_PROCESS
                              // ,JSON_SOLVE_FINISH and JSON_VALUE_TRANS;
    char * elem_str;          // this json elem's string
    char * value_str;         // this json elem's value string
    int  json_strlen;         //  if solve_state is JSON_SOLVE_PROCESS,
                              //  it is this json elem str's offset, if
                              // solve_state is JSON_SOLVE_FINISH,it is
                              // this json elem str's length                         // this
    int layer;                //
    int elem_no;              //
    Record_List childlist;    // this json's child list
    Record_List * curr_child; // when this json elme is solved, this
                              // pointer point to the child it was
                              // processing.
    struct json_elem_node * father;
}JSON_NODE;

void * get_first_json_child(void * father)
{
    JSON_NODE * father_node = (JSON_NODE *)father;
    father_node->curr_child =(Record_List *) (father_node->childlist.list.next);
    if(father_node->curr_child == &(father_node->childlist.list))
        return NULL;
    return father_node->curr_child->record;
}

void * get_next_json_child(void * father)
{
    JSON_NODE * father_node = (JSON_NODE *)father;
    if(father_node->curr_child == &(father_node->childlist.list))
        return NULL;
    father_node->curr_child = father_node->curr_child->list.next;
    return father_node->curr_child->record;
}

int json_get_type(void * node)
{
    if(node==NULL)
		return -EINVAL;
    JSON_NODE * json_node = (JSON_NODE *)node;
    return json_node->elem_type;
}
Record_List * get_new_Record_List(void * record)
{
    Record_List * newrecord = malloc(sizeof(Record_List));
    if(newrecord == NULL)
        return NULL;
    INIT_LIST_HEAD (&(newrecord->list));
    newrecord->record=record;
    return newrecord;
}

static inline int get_json_numvalue(char * valuestr,char * json_str)
{
    int i;
    int point=0;
     if(json_str[0]!='.')
    {
        if((json_str[0]<'0')||(json_str[0]>'9'))
            return -EINVAL;
    }
    for(i=0;i<1024;i++)
    {
        if(json_str[i]==0)
            return -EINVAL;
        if(IsValueEnd(json_str[i]))
            break;
        valuestr[i]=json_str[i];
    }
    if(i==0)
        return -EINVAL;
    if(i==1024)
        return -EINVAL;
    valuestr[i]=0;
    return i;
}

void * find_json_elem(char * name,void * root)
{
	JSON_NODE * root_node = (JSON_NODE * )root;
	JSON_NODE * this_node ;

	if(root_node->elem_type!=JSON_ELEM_MAP)
		return NULL;
        this_node = (JSON_NODE *)get_first_json_child(root);
	
	while(this_node != NULL)
	{
		if(strncmp(name,this_node->name,DIGEST_SIZE*2)==0)
			break;
		this_node=(JSON_NODE *)get_next_json_child(root);
	}
	return this_node;

}

static inline int get_json_boolvalue(char * valuestr,char * json_str)
{
   int i;
   if((json_str[0]!='b')||(json_str[0]!='B')
            ||(json_str[0]!='f')||(json_str[0]!='F'))
        return -EINVAL;
   for(i=0;i<6;i++)
   {
       if(json_str[i]==0)
           return -EINVAL;
       if(IsValueEnd(json_str[i]))
           break;
       valuestr[i]=json_str[i];
   }
   if(i==0)
        return -EINVAL;
   if(i==6)
        return -EINVAL;
   valuestr[i]=0;
   return i;
}

static inline int get_json_nullvalue(char * valuestr,char * json_str)
{
    int i;
    if((json_str[0]!='n')||(json_str[0]!='N'))
        return -EINVAL;
   for(i=0;i<6;i++)
   {
       if(json_str[i]==0)
           return -EINVAL;
       if(IsValueEnd(json_str[i]))
           break;
       valuestr[i]=json_str[i];
   }
   if(i==0)
        return -EINVAL;
   if(i==6)
        return -EINVAL;
   valuestr[i]=0;
   return i;

}

static inline int get_json_strvalue(char * valuestr,char * json_str)
{
    int i;
    int offset=0;
    for(i=0;i<1024;i++)
    {
        if(json_str[i]=='\"')
            break;
        if(json_str[i]==0)
            return -EINVAL;
	if(json_str[i]=='\\')
	    valuestr[offset]=json_str[++i];
	else
            valuestr[offset]=json_str[i];
	offset++;
    }
    if(i==1024)
        return -EINVAL;
    valuestr[offset]=0;
    return i;
}

void * get_json_node(void * father)
{
    JSON_NODE * newnode;
    JSON_NODE * father_node=(JSON_NODE *)father;
    newnode=malloc(sizeof(JSON_NODE));
    if(newnode==NULL)
        return NULL;
    memset(newnode,0,sizeof(JSON_NODE));
    INIT_LIST_HEAD(&(newnode->childlist.list));
    newnode->father=father;
    if(father!=NULL)
        newnode->layer=father_node->layer+1;
    Record_List * newrecord = get_new_Record_List(newnode);
    if(newrecord == NULL)
        return NULL;
    if(father_node!=NULL)
    {
        list_add_tail(newrecord,&(father_node->childlist.list));
        father_node->curr_child=newrecord;
    }
    return newnode;
}

void * get_json_value(void * father, int value_type)
{
    JSON_VALUE * newvalue;
    JSON_NODE * father_node=(JSON_NODE *)father;
    if((value_type !=JSON_ELEM_INIT)&&
           (value_type !=JSON_ELEM_NUM)&&
           (value_type !=JSON_ELEM_STRING)&&
           (value_type !=JSON_ELEM_BOOL))
        return NULL;
    if(father_node==NULL)
        return NULL;
    newvalue=malloc(sizeof(JSON_VALUE));
    if(newvalue==NULL)
        return NULL;
    memset(newvalue,0,sizeof(JSON_VALUE));
    Record_List * newrecord = get_new_Record_List(newvalue);
    if(newrecord == NULL)
        return NULL;
    list_add(newrecord,&(father_node->childlist.list));
    father_node->curr_child=newrecord;
    return newvalue;
}
int json_add_child(JSON_NODE * curr_node,void * child)
{
    Record_List * newrecord = get_new_Record_List(child);
    if(newrecord == NULL)
        return NULL;
    list_add(newrecord,&(curr_node->childlist.list));
    curr_node->curr_child=newrecord;
}

int json_solve_str(void ** root, char *str)
{
    JSON_NODE * root_node;
    JSON_NODE * father_node;
    JSON_NODE * curr_node;
    JSON_VALUE * curr_value;
    int value_type;
    char value_buffer[1024];

    char * tempstr;
    int i;
    int offset=0;
    int state=0;
    int ret;

    // give the root node value

    root_node=get_json_node(NULL);
    if(root_node==NULL)
        return -ENOMEM;
    father_node=NULL;
    curr_node=root_node;
    curr_node->layer=0;
    root_node->elem_type=JSON_ELEM_INIT;

    curr_node->solve_state=SOLVE_INIT;


    while(str[offset]!='\0')
    {
        switch(curr_node->solve_state)
        {
            case SOLVE_INIT:
                while(str[offset]!=0)
                {
                    if(!IsSplitChar(str[offset]))
                        break;
                    offset++;
                }
                if(str[offset]!='{')
                    return -EINVAL;
                // get an object node,then switch to the SOLVE_OBJECT
                father_node=curr_node;
                curr_node=get_json_node(father_node);
                curr_node->elem_type=JSON_ELEM_MAP;
                curr_node->solve_state=SOLVE_MAP;
                offset++;
                break;
           case SOLVE_MAP:
                while(str[offset]!=0)
                {
                    if(!IsSplitChar(str[offset]))
                        break;
                    offset++;
                }
                if(str[offset]!='\"'){
                    // if this map is empty,then finish this MAP
                    if(str[offset]=='}')
                    {
                        offset++;
                        curr_node->solve_state=SOLVE_UPGRADE;
                        break;
                    }
                    // if we should to find another elem
                    if(str[offset]==',')
                    {
                        offset++;
                        break;
                    }
                    else
                        return -EINVAL;
                }
                // we should build a name:value json node
                father_node=curr_node;
                curr_node=get_json_node(father_node);
                curr_node->elem_str=str+offset;
                offset++;
                curr_node->solve_state=SOLVE_NAME;
                break;
           case SOLVE_NAME:
                ret=get_json_strvalue(value_buffer,str+offset);
                if(ret<0)
                    return ret;
                if(ret>=DIGEST_SIZE*2)
                    return ret;
                offset+=ret;
		{
			 int len=strlen(value_buffer);
			 if(len<=DIGEST_SIZE*2)
               	        	 memcpy(curr_node->name,value_buffer,len+1);
			 else
               	        	 memcpy(curr_node->name,value_buffer,DIGEST_SIZE*2);
               		 offset++;
		}
                while(str[offset]!=0)
                {
                    if(!IsSplitChar(str[offset]))
                        break;
                    offset++;
                }
                if(str[offset]!=':')
                    return -EINVAL;
                offset++;
                curr_node->solve_state=SOLVE_VALUE;
                break;
           case SOLVE_VALUE:
                while(str[offset]!=0)
                {
                    if(!IsSplitChar(str[offset]))
                        break;
                    offset++;
                }
                if(str[offset]=='{')
                {
                // get an object node,then switch to the SOLVE_MAP
                   curr_node->elem_type=JSON_ELEM_MAP;
                   offset++;
                   curr_node->solve_state=SOLVE_MAP;
                   break;
                }
                if(str[offset]=='[')
                {
                // get an array node,then switch to the SOLVE_ARRAY
                    curr_node->elem_type=JSON_ELEM_ARRAY;
                    offset++;
                    curr_node->solve_state=SOLVE_ARRAY;
                    break;
                }
                if(str[offset]=='\"')   // value is JSON_STRING
                {
                    offset++;
                    i=get_json_strvalue(value_buffer,str+offset);
                    if(i>=0)
                    {
                        offset+=i+1;
                        curr_node->elem_type=JSON_ELEM_STRING;
                    }
                    else
                        return -EINVAL;
                }
                else
                {
                     i=get_json_numvalue(value_buffer,str+offset);
                     if(i>0)
                     {
                         offset+=i;
                         curr_node->elem_type=JSON_ELEM_NUM;
                     }
                     else
                     {
                          i=get_json_boolvalue(value_buffer,str+offset);
                          if(i>0)
                          {
                               offset+=i;
                               curr_node->elem_type=JSON_ELEM_BOOL;
                           }
                           else
                           {
                                 i=get_json_nullvalue(value_buffer,str+offset);
                                 if(i>0)
                                 {
                                       offset+=i;
                                       curr_node->elem_type=JSON_ELEM_NULL;
                                 }
                                 else
                                     return -EINVAL;

                            }

                       }
                 }
                 curr_node->value_str=dup_str(value_buffer,0);
                 curr_node->solve_state=SOLVE_UPGRADE;
                 break;
           case SOLVE_ARRAY:
                while(str[offset]!=0)
                {
                    if(!IsSplitChar(str[offset]))
                        break;
                    offset++;
                }
                if(str[offset]==']')
                {
                    offset++;
                    curr_node->solve_state=SOLVE_UPGRADE;
                    break;
                }
                // if we should to find another elem
                if(str[offset]==',')
                {
                    offset++;
                    break;
                }

            // we should build a name:value json node
                father_node=curr_node;
                curr_node=get_json_node(father_node);
                curr_node->elem_str=str+offset;
 //             offset++;
                curr_node->solve_state=SOLVE_VALUE;
                break;
            case SOLVE_UPGRADE:  // get value process
                curr_node->solve_state=SOLVE_FINISH;
                if(father_node->elem_type==JSON_ELEM_INIT)
                    break;
                curr_node=father_node;
                father_node=curr_node->father;
                break;

            default:
                return -EINVAL;
        }
        if(curr_node->solve_state==SOLVE_FINISH)
            break;
    }
    *root=curr_node;
    return offset;
}

int json_2_struct_write_elem(void * node,void * addr,TEMPLATE_ELEM * elem_template)
{
   JSON_NODE * json_node = (JSON_NODE *)node;

   struct struct_elem_attr * elem_attr;	
   BYTE * buf;
   int retval;
   int int_value;
   unsigned char char_value;
   UINT16 short_value;
   long long long_long_value;
   int i,j;
   BYTE * data;
   V_String * vstring;
   TEMPLATE_ELEM * elem_define;
   int define_value;

   retval=0;
   elem_attr=elem_template->elem_desc;
   switch(elem_attr->type) {
	case OS210_TYPE_STRING :
		if(json_node->elem_type!=JSON_ELEM_STRING)
			return -EINVAL;	
  		retval=elem_attr->size;
		memset(addr,0,retval);
		strncpy(addr,json_node->value_str,retval);
		break;
	case OS210_TYPE_INT :
  		retval=sizeof(int);
		if(json_node->elem_type!=JSON_ELEM_NUM)
			return -EINVAL;	
		int_value=atoi(json_node->value_str);
		memcpy(addr,&int_value,retval);
		break;
	case OS210_TYPE_ENUM :
  		retval=sizeof(int);
		if(json_node->elem_type == JSON_ELEM_NUM)
		{
			int_value=atoi(json_node->value_str);
			memcpy(addr,&int_value,retval);
		}
		else if(json_node->elem_type ==JSON_ELEM_STRING)
		{
			if(!strcmp(nulstring,json_node->value_str))
			{
				int_value=0;
			}
			else
			{
				NAME2VALUE * EnumList;
				if((elem_template->elem_var != NULL) && !IS_ERR(elem_template->elem_var))
					EnumList=elem_template->elem_var;
				else
					EnumList=elem_template->elem_desc->attr;

				if((EnumList==NULL)||IS_ERR(EnumList))
					return -EINVAL;
				char * string=json_node->value_str;
			
				for(i=0;EnumList[i].name!=NULL;i++)
				{
					if(!strcmp(EnumList[i].name,string))
					{	
						int_value=EnumList[i].value;
						memcpy(addr,&int_value,retval);
						break;
					}
				}
				if(EnumList[i].name==NULL)
					return -EINVAL;
			}
		}
		else
			return -EINVAL;
		break;
	case OS210_TYPE_FLAG :
  		retval=sizeof(int);
		if(json_node->elem_type == JSON_ELEM_NUM)
		{
			int_value=atoi(json_node->value_str);
			memcpy(addr,&int_value,retval);
		}
		else if(json_node->elem_type ==JSON_ELEM_STRING)
		{
			if(!strcmp(nulstring,json_node->value_str))
			{
				int_value=0;
			}
			else
			{
				NAME2VALUE * FlagList;
				if((elem_template->elem_var != NULL) && !IS_ERR(elem_template->elem_var))
					FlagList=elem_template->elem_var;
				else
					FlagList=elem_template->elem_desc->attr;

				if((FlagList==NULL)||IS_ERR(FlagList))
					return -EINVAL;
			
				int_value=0;
				char temp_string[256];
				int  stroffset=0;
				char * string=json_node->value_str;
	
				for(i=0;string[i]==' ';i++);
				if(string[i]==0)
					return 0;

				for(;i<strlen(string);i++)
				{
					// duplicate one flag bit string
					
					temp_string[stroffset++]=string[i];
					if((string[i+1]!='|') && (string[i+1]!=0))
						continue;
					i++;
					for(;string[i]==' ';i++)
					{
						if(string[i]==0)
							break;
					}
					 
					temp_string[stroffset]=0;
					stroffset=0;

				// find the flag's value

					for(j=0;FlagList[j].name!=NULL;j++)
					{
						if(strcmp(FlagList[j].name,temp_string))
							continue;
						int_value|=FlagList[j].value;
						break;
					}
					if(FlagList[j].name==NULL)
						return -EINVAL;
				}

				memcpy(addr,&int_value,retval);
			}
		}
		else
			return -EINVAL;
		break;
	case TPM_TYPE_UINT32 :
  		retval=sizeof(int);
		if(json_node->elem_type == JSON_ELEM_NUM)
		{
			int_value=atoi(json_node->value_str);
  			*(int *)addr=Decode_UINT32(&int_value);
		}
		else
			return -EINVAL;
		break;
	case OS210_TYPE_TIME :
  		retval=sizeof(time_t);
//		memcpy(addr,elem_data,retval);
		break;
	case OS210_TYPE_UCHAR :
  		retval=sizeof(unsigned char);
		memcpy(addr,json_node->value_str,retval);
		break;
	case OS210_TYPE_USHORT :
  		retval=sizeof(unsigned short);
		if(json_node->elem_type == JSON_ELEM_NUM)
		{
			short_value=atoi(json_node->value_str);
			memcpy(addr,&short_value,retval);
		}
		else
			return -EINVAL;
		break;
	case TPM_TYPE_UINT16 :
  		retval=sizeof(UINT16);
		if(json_node->elem_type == JSON_ELEM_NUM)
		{
			short_value=atoi(json_node->value_str);
  			*(UINT16 *)addr=Decode_UINT16(&short_value);
		}
		else
			return -EINVAL;
		break;
	case OS210_TYPE_LONGLONG:
  		retval=sizeof(long long);
		if(json_node->elem_type == JSON_ELEM_NUM)
		{
			long_long_value=atoi(json_node->value_str);
			memcpy(addr,&long_long_value,retval);
		}
		else
			return -EINVAL;
		break;
	case TPM_TYPE_UINT64 :
  		retval=sizeof(UINT64);
		if(json_node->elem_type == JSON_ELEM_NUM)
		{
			long_long_value=atoi(json_node->value_str);
  			*(UINT64 *)addr=Decode_UINT64(&long_long_value);
		}
		else
			return -EINVAL;
		break;
	case OS210_TYPE_BINDATA:
		if(json_node->elem_type != JSON_ELEM_STRING)
			return -EINVAL;
  		retval=elem_attr->size;
		radix64_to_bin(addr,bin_to_radix64_len(retval),json_node->value_str);
		break;
	case OS210_TYPE_BITMAP:
		if(json_node->elem_type != JSON_ELEM_STRING)
			return -EINVAL;
		{
			char * tempstring;
			BYTE * tempbuf;
			retval=elem_attr->size;
			tempbuf=(BYTE * )addr;
			tempstring=json_node->value_str;
			for(i=0;i<retval;i++)
			{
				tempbuf[i]=0;
				while(*tempstring==' ')
					tempstring++;
				for(j=0;j<8;j++)
				{
					if((*tempstring!= '0') &&(*tempstring!='1'))
						return -EINVAL;
					tempbuf[i]=tempbuf[i]<<1+(*tempstring-'0');
					tempstring++;	
				}
			}
		}
		break;
	case OS210_TYPE_HEXDATA:
		if(json_node->elem_type != JSON_ELEM_STRING)
			return -EINVAL;
		{
			char * tempstring;
			BYTE * tempbuf;
			retval=elem_attr->size;
			tempbuf=(BYTE * )addr;
			tempstring=json_node->value_str;
			for(i=0;i<retval;i++)
			{
				tempbuf[i]=0;
				while(*tempstring==' ')
					tempstring++;
				for(j=0;j<2;j++)
				{
					if((*tempstring>='0') &&(*tempstring<='9'))
					{
						tempbuf[i]=tempbuf[i]*0x10+(*tempstring-'0');
					}
					else if((*tempstring>='A') &&(*tempstring<='F'))
					{
						tempbuf[i]=tempbuf[i]*0x10+(*tempstring-'A'+9);
					}
					else if((*tempstring>='a') &&(*tempstring<='f'))
					{
						tempbuf[i]=tempbuf[i]*0x10+(*tempstring-'a'+9);
					}
					else
						return -EINVAL;
					tempstring++;	
				}
			}
		}
		break;
	case OS210_TYPE_BINARRAY:
		if(json_node->elem_type != JSON_ELEM_ARRAY)
			return -EINVAL;
		{
	  		retval=elem_attr->size*(int)(elem_attr->attr);
			memset(addr,0,retval);
		
			JSON_VALUE * curr_value;
			for(i=0;i<(int)(elem_attr->attr);i++) 
			{
				if(i==0)
					curr_value=get_first_json_child(json_node);
				else
					curr_value=get_next_json_child(json_node);
				if(curr_value==NULL)
					break;
				if(curr_value->value_type!=JSON_ELEM_STRING)
					return -EINVAL;
				radix64_to_bin(addr+i*elem_attr->size,bin_to_radix64_len(elem_attr->size),json_node->value_str);
			}
				
		}

		break;
	case OS210_TYPE_VSTRING:
		if(json_node->elem_type != JSON_ELEM_STRING)
			return -EINVAL;
		int_value=strlen(json_node->value_str);
		vstring = (V_String *)addr;
		vstring->length=int_value;
		if((vstring->length <0) || vstring->length> OS210_MAX_BUF)
		{
			retval=-EINVAL;	
		}
		vstring->String=kmalloc(vstring->length,GFP_KERNEL);
		if(vstring->String==NULL)
			return -ENOMEM;
		memcpy(vstring->String,json_node->value_str,vstring->length);
		retval=sizeof(V_String);
		break;
	case OS210_TYPE_ESTRING:
		if(json_node->elem_type != JSON_ELEM_STRING)
			return -EINVAL;
		{
			char * estring;
			retval=strlen(json_node->value_str);
			if(retval<0)
				retval=-EINVAL;	
			if((elem_attr->size!=0) && (retval>elem_attr->size))
				retval=-EINVAL;	
			retval++;
			estring=kmalloc(retval,GFP_KERNEL);
			if(estring==NULL)
				return -ENOMEM;
			memcpy(estring,json_node->value_str,retval);
			*(char **)addr=estring;
			retval=sizeof(char *);
		}
		break;

	case OS210_TYPE_DEFINE:
		if(json_node->elem_type != JSON_ELEM_STRING)
			return -EINVAL;
		elem_define=(TEMPLATE_ELEM *)(elem_template->elem_var);
		retval=elem_attr->size*(*(int*)(elem_define->elem_var));
		if(retval!=radix64_to_bin(addr,strlen(json_node->value_str),json_node->value_str))
			return -EINVAL;
		break;
	case OS210_TYPE_DEFSTR:
		if(json_node->elem_type != JSON_ELEM_STRING)
			return -EINVAL;
		elem_define=(TEMPLATE_ELEM *)(elem_template->elem_var);
		retval=elem_attr->size*(*(int*)(elem_define->elem_var));
		{
			char * estring;
			retval++;
			estring=kmalloc(retval,GFP_KERNEL);
			if(estring==NULL)
				return -ENOMEM;
			memcpy(estring,json_node->value_str,retval);
			*(char **)addr=estring;
		}
		retval=sizeof(char *);
		break;
		
	case OS210_TYPE_DEFSTRARRAY:
		if(json_node->elem_type != JSON_ELEM_ARRAY)
			return -EINVAL;
		elem_define=(TEMPLATE_ELEM *)(elem_template->elem_var);
		define_value=*(int *)elem_define->elem_var;
		if(define_value<0)
			return -EINVAL;
		if(define_value>32768)
			return -EINVAL;
		retval=elem_attr->size*define_value;

		{
			char * estring;
			estring=kmalloc(retval,GFP_KERNEL);
			if(estring==NULL)
			return -ENOMEM;
			memset(estring,0,retval);
		
			JSON_NODE * curr_node;
//			JSON_VALUE * curr_value;
			for(i=0;i<define_value;i++) 
			{
				if(i==0)
					curr_node=get_first_json_child(json_node);
				else
					curr_node=get_next_json_child(json_node);
				if(curr_node==NULL)
					break;
				if(curr_node->elem_type!=JSON_ELEM_STRING)
					return -EINVAL;
//				radix64_to_bin(addr+i*elem_attr->size,bin_to_radix64_len(elem_attr->size),json_node->value_str);
				strncpy(estring+i*elem_attr->size,curr_node->value_str,elem_attr->size);
			}
			*(char **)addr=estring;	
		}
		break;
	case OS210_TYPE_ORGCHAIN:
		retval= 0;
//		retval = os210_struct_size_sum(elem_attr->attr);
		break;
	case OS210_TYPE_NODATA:
	default:
		break;
	}	
 	return retval;
}

int struct_read_json_elem(char * name,void * addr, void * node,void * struct_template)
{
	JSON_NODE * json_node=(JSON_NODE *)node;
	int * define_value;

	TEMPLATE_ELEM * elem;
	int addr_offset;
	char buffer[4096];
	int ret;
	elem=(TEMPLATE_ELEM *)read_elem_addr(name,struct_template);
	if((elem == NULL)||IS_ERR(elem))
		return -EINVAL;
	addr_offset=struct_get_elem_addr(elem,struct_template);
	if(addr_offset<0)
		return addr_offset;
	ret=json_2_struct_write_elem(json_node,addr+addr_offset,elem);
	// if this elem's elem_var is not empty, then it is a defining elem,we should get its value for later use
	switch(elem->elem_desc->type)
	{
		case OS210_TYPE_INT:
		case OS210_TYPE_UCHAR:
		case OS210_TYPE_USHORT:
		case OS210_TYPE_LONGLONG:
		case OS210_TYPE_STRING:
		case OS210_TYPE_ESTRING:
		case OS210_TYPE_JSONSTRING:
		case OS210_TYPE_VSTRING:
		case TPM_TYPE_UINT64:
		case TPM_TYPE_UINT32:
		case TPM_TYPE_UINT16:
		case DB_TYPE_STRING:
		case DB_TYPE_INT:
		case ASN_TYPE_INT:
		case ASN_TYPE_LONGINT:

	// if this elem's elem_var is not empty, then it is a defining elem,we should get its value for later use
			if(elem->elem_var != 0)
			{	
				define_value = (int *)(elem->elem_var);
				*define_value = struct_get_int_value(addr+addr_offset,elem); 
			}
		default:
			break;
	}
	return ret;
}

#define MAX_LAYER 10

int json_2_struct(void * root,void * addr, void * struct_template)
{
    JSON_NODE * curr_node;
    JSON_NODE * father_node;
    JSON_VALUE * curr_value;
    int  namelen;
    int nameoffset[MAX_LAYER];
    char namebuffer[MAX_LAYER*DIGEST_SIZE*2];
    int curr_layer=0;
    int i;
    int ret;

    for(i=0;i<MAX_LAYER;i++)
	  nameoffset[i]=0;

    father_node =root;
    if(father_node==NULL)
	return -EINVAL;
    if(father_node->elem_type!=JSON_ELEM_MAP)
	return -EINVAL;
     curr_node=get_first_json_child(father_node);
     curr_layer=1;

    do {
        if(curr_node==NULL)
	{
		if(father_node ==root)
			break;
		else
		{
			curr_node=father_node;
			father_node=curr_node->father;
			curr_layer--;
			namebuffer[nameoffset[curr_layer]]=0;
			curr_node=get_next_json_child(father_node);
			continue;
		}
	}
	namelen=strlen(curr_node->name);
        if(namelen>64)
		namelen=64;
	if(curr_layer>1)
	{
		namebuffer[nameoffset[curr_layer-1]+1]='.';
      	        memcpy(namebuffer+nameoffset[curr_layer-1]+1,curr_node->name,namelen);
        	nameoffset[curr_layer]=nameoffset[curr_layer-1]+namelen+1;
	}
	else
	{
      	        memcpy(namebuffer,curr_node->name,namelen+1);
        	nameoffset[curr_layer]=namelen;
	}
	namebuffer[nameoffset[curr_layer]]=0;

        if(curr_node->elem_type==JSON_ELEM_MAP)
        {
            father_node=curr_node;
            curr_node=get_first_json_child(father_node);
	    curr_layer++;
	    continue;
        }
	ret=struct_read_json_elem(namebuffer,addr,curr_node,struct_template);
        if(ret<0)
		return -EINVAL;
	curr_node=get_next_json_child(father_node);		

    }while(1);
    return 0;
}

int struct_2_json_write_elem(void * addr,char * json_str,TEMPLATE_ELEM * elem_template,int *stroffset)
{
	struct struct_elem_attr * elem_attr;
	const int bufsize=8192;
   	BYTE buf[bufsize];
	char * tempbuf;
	int retval;
	int int_value;
	unsigned char char_value;
	unsigned short short_value;
	long long long_long_value;
	int i,j;
	BYTE * data;
	V_String vstring;
	int len;

	char * string=json_str;

	TEMPLATE_ELEM * elem_define;
	int define_value;


	elem_attr=elem_template->elem_desc;

	switch(elem_attr->type) {
		case OS210_TYPE_STRING :
	  		retval=elem_attr->size;
			int_value=strlen(addr);
			*(string+*stroffset)='\"';
			(*stroffset)++;
			if(int_value >=retval)
			{
				memcpy(string+*stroffset,addr,retval);
				*stroffset+=retval;
			}
			else
			{
				memcpy(string+*stroffset,addr,int_value);
				*stroffset+=int_value;
			}
			*(string+*stroffset)='\"';
			(*stroffset)++;
			break;
		case OS210_TYPE_INT :
		case TPM_TYPE_UINT32 :
			int_value=*(int *)addr;
			snprintf(string+*stroffset,bufsize,"%d",int_value);
			*stroffset+=strlen(string+*stroffset);
  			retval=sizeof(int);
			break;
		case OS210_TYPE_ENUM :
		{
  			retval=sizeof(int);
			int_value=*(int *)addr;
			*(string+*stroffset)='\"';
			(*stroffset)++;
			if(int_value==0)
			{
				len=strlen(nulstring);
				memcpy(string+*stroffset,nulstring,len);
				*stroffset+=len;
			}	
			else
			{

				NAME2VALUE * EnumList;
				if((elem_template->elem_var != NULL) && !IS_ERR(elem_template->elem_var))
					EnumList=elem_template->elem_var;
				else
					EnumList=elem_template->elem_desc->attr;

				if((EnumList==NULL)||IS_ERR(EnumList))
					return -EINVAL;
			
			
				for(i=0;EnumList[i].name!=NULL;i++)
				{
					if(EnumList[i].value==int_value)
					{
						len=strlen(EnumList[i].name);
						memcpy(string+*stroffset,EnumList[i].name,len);
						*stroffset+=len;
						break;
					}
				}
				if(EnumList[i].name==NULL)
					return -EINVAL;
			}
		}
		*(string+*stroffset)='\"';
		(*stroffset)++;
		break;
	case OS210_TYPE_FLAG :
		{
  			retval=sizeof(int);
			int_value=*(int *)addr;
			*(string+*stroffset)='\"';
			(*stroffset)++;
			if(int_value==0)
			{
				len=strlen(nulstring);
				memcpy(string+*stroffset,nulstring,len);
				*stroffset+=len;
			}	
			else
			{
				NAME2VALUE * FlagList;
				if((elem_template->elem_var != NULL) && !IS_ERR(elem_template->elem_var))
					FlagList=elem_template->elem_var;
				else
					FlagList=elem_template->elem_desc->attr;


				if((FlagList==NULL)||IS_ERR(FlagList))
					return -EINVAL;
			
				j=0;   // count the match flag num
				for(i=0;FlagList[i].name!=NULL;i++)
				{
					if(FlagList[i].value & int_value)
					{
						if(j!=0)  // not the first flag
						{
							sprintf(string+*stroffset,"|");
							(*stroffset)++;
	
						}	
						j++;
						int length=strlen(FlagList[i].name);
						memcpy(string+*stroffset,FlagList[i].name,length);
						*stroffset+=length;
					}
				}
			}
		}
		*(string+*stroffset)='\"';
		(*stroffset)++;
		break;
	case OS210_TYPE_TIME:
		{
			retval=sizeof(time_t);
			struct tm * tm_time;
			time_t * t_time;
			if(tm_time==NULL)
				return -ENOMEM;
			*(string+*stroffset)='\"';
			(*stroffset)++;

			tm_time = localtime(addr);
			if(tm_time != NULL)
			{
				sprintf(string+*stroffset,
				"%4d%2d%2d%2d%2d%2d",
				tm_time->tm_year+1900,
				tm_time->tm_mon+1,
				tm_time->tm_mday,
				tm_time->tm_hour,
				tm_time->tm_min,
				tm_time->tm_sec);
			}
			else
				return -EINVAL;
			*stroffset+=strlen(string+*stroffset);
		}
		*(string+*stroffset)='\"';
		(*stroffset)++;
		break;
	case OS210_TYPE_UCHAR :
		retval=sizeof(unsigned char);
		sprintf(string+*stroffset,"%d",*(unsigned char *)addr);
		*stroffset+=strlen(string+*stroffset);
		break;
	case OS210_TYPE_USHORT :
	case TPM_TYPE_UINT16 :
		retval=sizeof(unsigned short);
		sprintf(string+*stroffset,"%d",*(unsigned short *)addr);
		*stroffset+=strlen(string+*stroffset);
		break;
	case OS210_TYPE_LONGLONG:
	case TPM_TYPE_UINT64 :
		retval=sizeof(unsigned long long);
		sprintf(string+*stroffset,"%d",*(unsigned long long *)addr);
		*stroffset+=strlen(string+*stroffset);
		break;
	case OS210_TYPE_BINDATA:
		retval=elem_attr->size;
		memset(buf,0,bufsize);
		bin_to_radix64(buf,elem_attr->size,addr);	
		*(string+*stroffset)='\"';
		(*stroffset)++;
		sprintf(string+*stroffset,"%s",buf);
		*stroffset+=strlen(string+*stroffset);

		*(string+*stroffset)='\"';
		(*stroffset)++;

		break;
	case OS210_TYPE_BITMAP:
		retval=elem_attr->size;
		tempbuf=(BYTE * )addr;
		*(string+*stroffset)='\"';
		(*stroffset)++;
		for(i=0;i<retval;i++)
		{
			char_value=tempbuf[i];
			for(j=0;j<8;j++)
			{
				*(string+*stroffset) = char_value%2+'0';
				(*stroffset)++;
				char_value>>=1;
			}
			*(string+*stroffset)=' ';
			(*stroffset)++;
		}
		*(string+*stroffset)='\"';
		(*stroffset)++;
		break;
	case OS210_TYPE_HEXDATA:
		retval=elem_attr->size;
		tempbuf=(BYTE * )addr;
		*(string+*stroffset)='\"';
		(*stroffset)++;
		for(i=0;i<retval;i++)
		{
			int tempdata;
			char_value=tempbuf[i];
			for(j=0;j<2;j++)
			{
				tempdata=char_value>>4;
				if(tempdata>9)
					*(string+*stroffset) = tempdata-9+'a';
				else
					*(string+*stroffset) = tempdata+'0';
				(*stroffset)++;
				if(j!=1)
				char_value<<=4;
			}
		}
		*(string+*stroffset)='\"';
		(*stroffset)++;
		break;
	case OS210_TYPE_BINARRAY:
		retval=elem_attr->size*(int)(elem_attr->attr);
		memset(buf,0,bufsize);
		for(i=0;i<elem_attr->size;i++)
		{
			*(string+*stroffset)='\"';
			(*stroffset)++;
			bin_to_radix64(buf,(int)(elem_attr->attr),addr+i*(int)(elem_attr->attr));	
			sprintf(string+*stroffset,"%s ",buf);
			string+=strlen(string+*stroffset);
			*(string+*stroffset)='\"';
			(*stroffset)++;
			*(string+*stroffset)=',';
			(*stroffset)++;
		}
		break;
	case OS210_TYPE_VSTRING:
		vstring.length=*(UINT16 *)addr;
		if((vstring.length <0) || (vstring.length>OS210_MAX_BUF))
		{
			return retval;	
		}
		*(string+*stroffset)='\"';
		(*stroffset)++;
		retval=sizeof(UINT16)+vstring.length;
		vstring.String= (BYTE *)addr+sizeof(UINT16);
		memcpy(string+*stroffset,vstring.String,vstring.length);
		*stroffset+=vstring.length;
		*(string+*stroffset)='\"';
		(*stroffset)++;
		break;
	case OS210_TYPE_ESTRING:
		{
			int length;
			if(*(char **)addr==NULL)
			{
				length=0;
			}
			else
			{
            			length=strlen(*(char **)addr);
			}
			if(length <0)
			{
				retval=-EINVAL;	
			}
			if((elem_attr!=0) &&(length>elem_attr->size))
			{
				retval=-EINVAL;	
			}
			*(string+*stroffset)='\"';
			(*stroffset)++;
			if(length>0)
            			sprintf(string+*stroffset,"%s",*(char **)addr);
			*stroffset+=length;
			retval=length+1;
			*(string+*stroffset)='\"';
			(*stroffset)++;
		}
		break;

	case OS210_TYPE_ORGCHAIN:
	 	retval= 0;		
		break;
	case OS210_TYPE_DEFINE:
		elem_define=(TEMPLATE_ELEM *)(elem_template->elem_var);
		retval=elem_attr->size*(*(int*)(elem_define->elem_var));
		int_value=bin_to_radix64(buf,retval,addr);	
		if(int_value!=bin_to_radix64_len(retval))
				return -EINVAL;
		*(string+*stroffset)='\"';
		(*stroffset)++;
		sprintf(string+*stroffset,"%s",buf);
		*stroffset+=int_value;
		*(string+*stroffset)='\"';
		(*stroffset)++;
		break;
	case OS210_TYPE_DEFSTR:
		elem_define=(TEMPLATE_ELEM *)(elem_template->elem_var);
		retval=elem_attr->size*(*(int*)(elem_define->elem_var));
		*(string+*stroffset)='\"';
		(*stroffset)++;
		memcpy(string+*stroffset,*(char **)addr,retval);
		*stroffset+=retval;
		*(string+*stroffset)='\"';
		(*stroffset)++;
		break;

	case OS210_TYPE_DEFSTRARRAY:
		elem_define=(TEMPLATE_ELEM *)(elem_template->elem_var);
		define_value=*(int *)elem_define->elem_var;
		retval=elem_attr->size*(*(int*)(elem_define->elem_var));
		if(define_value<0)
			return -EINVAL;
		if(define_value>32768)
			return -EINVAL;
		int_value=0;
		char * strbuf=malloc(elem_attr->size+1);
		if(strbuf==NULL)
			return -ENOMEM;
		for(i=0;i<define_value;i++)
		{
			strbuf[elem_attr->size]=0;
			*(string+*stroffset)='\"';
			(*stroffset)++;
			memcpy(strbuf,*(char **)addr+i*elem_attr->size,elem_attr->size);
			sprintf(string+*stroffset,"%s",strbuf);
			int_value=strlen(string+*stroffset);
			string[*stroffset+int_value]=' ';
			*stroffset+=int_value+1;
			*(string+*stroffset)='\"';
			(*stroffset)++;
			*(string+*stroffset)=',';
			(*stroffset)++;
		}
		free(strbuf);	
		break;
		
	case OS210_TYPE_NODATA:
	default:
		break;
	}	
 	return retval;
}

#define MAX_NAME_DEPTH 10

int struct_2_json( void * addr,char * json_str,void * template,int * stroffset)
{
	struct struct_template * struct_template;
	struct struct_template * curr_struct;
	void * stack;
	int addroffset=0;
    int offset=0;
	int i;
	int value;
	int * define_value;
	int retval;
	char * string=json_str;
    int namelen;

	TEMPLATE_ELEM * struct_elem;
	// use a pointer stack to finish the throughout of the template
	stack=init_pointer_stack(MAX_NAME_DEPTH);
	
	if(IS_ERR(stack))
		return stack;

	struct_template=(struct struct_template *)template;
	curr_struct = struct_template;
	
	i=0;
	// get the first elem
	*(string+*stroffset)='{';
	(*stroffset)++;

	struct_elem=curr_struct->elem_list;
	while(1){
		// if this elem is out of the elemlist's range, then we should pop a pointer of the stack
		if(struct_elem >= curr_struct->elem_list+curr_struct->elem_num-1)
		{
			struct_elem = pointer_stack_pop(stack);
			// if pop failed, it means curr_struct is the root struct template, and we finish the throughout. 

//			if(IS_ERR(struct_elem))
//				break;
			if(struct_elem==-ERANGE)
				break;
			//  else, we changes the curr_struct;
			curr_struct=struct_elem->elem_struct;
		}

		// if this elem is a substruct, push the next elem in this struct, then get the first elem of the substruct as the curr struct_elem; 
		while(struct_elem->elem_desc->type == OS210_TYPE_ORGCHAIN)
		{
			pointer_stack_push(stack,struct_elem+1);
			curr_struct=(struct struct_template *)(struct_elem->elem_var);
			struct_elem=curr_struct->elem_list;
		}
		switch(struct_elem->elem_desc->type)
		{
			case OS210_TYPE_INT:
			case OS210_TYPE_UCHAR:
			case OS210_TYPE_USHORT:
			case OS210_TYPE_LONGLONG:
			case OS210_TYPE_STRING:
			case OS210_TYPE_ESTRING:
			case OS210_TYPE_VSTRING:
			case TPM_TYPE_UINT64:
			case TPM_TYPE_UINT32:
			case TPM_TYPE_UINT16:
			case DB_TYPE_STRING:
			case DB_TYPE_INT:
			case ASN_TYPE_INT:
			case ASN_TYPE_LONGINT:

		// if this elem's elem_var is not empty, then it is a defining elem,we should get its value for later use
				if(struct_elem->elem_var != 0)
				{	
					define_value = (int *)(struct_elem->elem_var);
					*define_value = struct_get_int_value(addr+addroffset,struct_elem); 
				}
			default:
				break;
		}
		//  write struct value to addr
        namelen=strlen(struct_elem->elem_desc->name);
        if(namelen<=0)
            return -EINVAL;
        if(namelen>128)
            return -EINVAL;
        char buffer[132];
        sprintf(buffer,"\"%s\":",struct_elem->elem_desc->name);
        namelen=strlen(buffer);
        memcpy(string+*stroffset,buffer,namelen+1);
        *stroffset+=namelen;
		retval = struct_2_json_write_elem(addr+addroffset,string,struct_elem,stroffset);
		if(retval<0)
		{
			free_pointer_stack(stack);
			return retval;
		}
        if((offset=struct_get_elem_size(struct_elem))<0)
        {
            free_pointer_stack(stack);
            return offset;
        }
        addroffset+=offset;
        *(string+*stroffset)=',';
		(*stroffset)++;
		struct_elem++;
	}
	free_pointer_stack(stack);
	*(string+*stroffset)='}';
	(*stroffset)++;
	*(string+*stroffset)=0;
	return addroffset;
}

int get_json_value_from_node(void * node,void * value,int max_len)
{
    int ret;
    JSON_NODE * json_node;
    if(node==NULL)
        return -EINVAL;
    json_node=(JSON_NODE *)node;
    if(json_node->value_str==NULL)
        return 0;
//    if(json_node->elem_type==JSON_ELEM_NUM)
//   {
//	memcpy(value,json_node->value_str,sizeof(int));
//	return sizeof(int);
//   }
    ret=strlen(json_node->value_str);
    if(ret>max_len)
        ret=max_len;
     if(json_node->elem_type==JSON_ELEM_NUM)
     {
	*(int *)value =atoi(json_node->value_str);
		return sizeof(int);
    }
    else
   	 Memcpy(value,json_node->value_str,ret);
    if(ret<max_len)
	    ((char *)value)[ret]=0;
    return ret;
}

int get_json_name_from_node(void * node,char * name)
{
    int ret;
    JSON_NODE * json_node;
    if(node==NULL)
        return -EINVAL;
    json_node=(JSON_NODE *)node;
    if(json_node->name==NULL)
        return 0;
    ret=strlen(json_node->name);
    
    if(ret>DIGEST_SIZE*2)
        ret=DIGEST_SIZE*2;
    Memcpy(name,json_node->name,ret);
    if(ret<DIGEST_SIZE*2)
	    name[ret]=0;
    return ret;
}
