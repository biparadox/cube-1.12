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
//#include "cipher.h"
#include "radix64.h"
#include "struct_internal.h"


#define os210_print_buf 400
#define OS210_MAX_BUF   4096

const char * nulstring="NULL";

UINT16
Decode_UINT16(BYTE * in)
{
	UINT16 temp = 0;
	temp = (in[1] & 0xFF);
	temp |= (in[0] << 8);
	return temp;
}

void
UINT32ToArray(UINT32 i, BYTE * out)
{
	out[0] = (BYTE) ((i >> 24) & 0xFF);
	out[1] = (BYTE) ((i >> 16) & 0xFF);
	out[2] = (BYTE) ((i >> 8) & 0xFF);
	out[3] = (BYTE) i & 0xFF;
}

void
UINT64ToArray(UINT64 i, BYTE *out)
{
	out[0] = (BYTE) ((i >> 56) & 0xFF);
	out[1] = (BYTE) ((i >> 48) & 0xFF);
	out[2] = (BYTE) ((i >> 40) & 0xFF);
	out[3] = (BYTE) ((i >> 32) & 0xFF);
	out[4] = (BYTE) ((i >> 24) & 0xFF);
	out[5] = (BYTE) ((i >> 16) & 0xFF);
	out[6] = (BYTE) ((i >> 8) & 0xFF);
	out[7] = (BYTE) i & 0xFF;
}

void
UINT16ToArray(UINT16 i, BYTE * out)
{
	out[0] = ((i >> 8) & 0xFF);
	out[1] = i & 0xFF;
}

UINT64
Decode_UINT64(BYTE *y)
{
	UINT64 x = 0;

	x = y[0];
	x = ((x << 8) | (y[1] & 0xFF));
	x = ((x << 8) | (y[2] & 0xFF));
	x = ((x << 8) | (y[3] & 0xFF));
	x = ((x << 8) | (y[4] & 0xFF));
	x = ((x << 8) | (y[5] & 0xFF));
	x = ((x << 8) | (y[6] & 0xFF));
	x = ((x << 8) | (y[7] & 0xFF));

	return x;
}

UINT32
Decode_UINT32(BYTE * y)
{
	UINT32 x = 0;

	x = y[0];
	x = ((x << 8) | (y[1] & 0xFF));
	x = ((x << 8) | (y[2] & 0xFF));
	x = ((x << 8) | (y[3] & 0xFF));

	return x;
}

//const int MAX_ARRAY_ELEM_NUM = 128;
/*
typedef struct  tag_template_elem
{
	void   * elem_struct;
	struct struct_elem_attr * elem_desc;
	void * elem_var;
}TEMPLATE_ELEM;

struct struct_template
{
	int elem_num;
	struct tag_struct_template * parent_struct;
	struct struct_elem_attr * struct_desc;
	TEMPLATE_ELEM * elem_list;
	void * var_list;
};
*/
void * get_desc_from_template(void * template)
{
	struct struct_template * struct_template=(struct struct_template * )template;
	if((template == NULL) || IS_ERR(template))
	{
		return NULL;
	}
	return struct_template->struct_desc;
}

void * dup_str(char * src,int size)
{
	char * dest;
	int len;
	if(src==NULL)
		return src;
	
	len=strlen(src)+1;
	if(size==0)
	{
		dest=kmalloc(len,GFP_KERNEL);
		if(dest==NULL)
			return -ENOMEM;
		memcpy(dest,src,len);
	}
	else
	{
		dest=kmalloc(size,GFP_KERNEL);
		if(dest==NULL)
			return -ENOMEM;
		if(len<=size)
			memcpy(dest,src,len);
		else
			memcpy(dest,src,size);

	}
	return dest;
}

static inline int IsAValidChar(char c)
{
	if((c=='\t')||(c=='\n')||(c=='\0')||(c=='\r'))
	{
		return 0;
	}
	return 1;
}
// read an struct elem from a string,the tail of this string is \t, \n,\0 or
// \r,if \t ,\n,\0 or \r in the head of the string,ignore them.
//

static inline int IsLinesEnd(char c)
{
	if((c=='\n')||(c=='\0')||(c=='\r'))
	{
		return 0;
	}
	return 1;
}

struct struct_template * struct_template_init(struct struct_elem_attr * struct_desc)
{
	struct struct_template * template;
	struct struct_elem_attr * curr_desc;
	struct struct_elem_attr * curr_elem;
	int struct_elem_num;
	int i=0;


	// malloc the basic struct template and init it;
	template =kmalloc(sizeof(struct struct_template),GFP_KERNEL);

	if(template==NULL)
		return -ENOMEM;
	memset(template,0,sizeof(struct struct_template));

	template->elem_num=0;
	template->parent_struct=NULL;
	template->var_list=NULL;
	template->elem_list=NULL;

	// if struct_desc is null, we only return an empte struct_template;
	if(struct_desc == NULL)
		return template;
	
	// else, we will fill the struct_template, but not include the substruct and the extern defined variable;
	

	template->struct_desc=struct_desc;

	curr_desc=template->struct_desc;
	curr_elem=template->struct_desc;

	// step 1: compute this struct's elem number and select all the substruct from it 
	while((curr_elem->type != OS210_TYPE_ENDDATA)&&(curr_elem->name !=NULL))
	{
	
		i++;
		curr_elem=curr_desc+i;
		if(i>=MAX_ARRAY_ELEM_NUM)
		{
			kfree(template);
			return -EINVAL;
		}

	}	
		// alloc this struct's var_list(with the elem_list togther); 
	struct_elem_num=i+1;
	template->elem_num=struct_elem_num;

	template->var_list=(void *)kmalloc(sizeof(void *)*struct_elem_num+sizeof(TEMPLATE_ELEM)*struct_elem_num,GFP_KERNEL);

	if(template->var_list==NULL)
	{
		kfree(template);
		return -ENOMEM;
	}

	template->elem_list=(TEMPLATE_ELEM *)(template->var_list+struct_elem_num*sizeof(void *));
	memset(template->var_list,0,sizeof(void *)*struct_elem_num);
	memset(template->elem_list,0,sizeof(TEMPLATE_ELEM)*struct_elem_num);

	// init the value of the elem_list
	
	for(i=0;i<struct_elem_num;i++)
	{
		template->elem_list[i].elem_struct=template;
		template->elem_list[i].elem_desc=struct_desc+i;
		if((struct_desc[i].type==OS210_TYPE_ENUM)
			||(struct_desc[i].type==OS210_TYPE_FLAG))
		{
			template->elem_list[i].elem_var=struct_desc[i].attr;
		}
	}
	return template;
}

#define MAX_NAME_LEN 512
#define MAX_NAME_DEPTH 20

int splitname(char * pathname,char ** pathelem)
{
	int i,depth;
	i=0;
	depth=0;

	while(pathname[i]==' ')
		i++;
		
	pathelem[depth]=pathname+i;
		
	while(pathname[i]!=0)
	{
		if(pathname[i]=='.')
		{
			pathname[i]=0;
			pathelem[++depth]=pathname+i+1;
			if(depth>=MAX_NAME_DEPTH)
				return -EINVAL;
		}
		i++;
		if(i>=MAX_NAME_LEN)
			return -EINVAL;
	}
	return depth;
}


struct struct_template * get_root_template(struct struct_template * template)
{
	struct struct_template * curr_template;
	if(template == NULL)
		return NULL;
	curr_template =template;
	while(curr_template->parent_struct != NULL)
		curr_template=curr_template->parent_struct;
	return curr_template;
}


TEMPLATE_ELEM * get_elem_by_name(char * name,struct struct_template * template)
{

	int i;
	int elem_num;
	TEMPLATE_ELEM * curr_elem;
	
	elem_num=template->elem_num;

	for(i=0;i<elem_num;i++)
	{
		curr_elem=&(template->elem_list[i]);	
		if(curr_elem->elem_desc->type==OS210_TYPE_ENDDATA)
			return NULL;
		if(!strcmp(name,curr_elem->elem_desc->name))
		{
			return curr_elem;
		}
	}
	return NULL;	
}

TEMPLATE_ELEM * get_elem_by_name_with_mark(char * name,struct struct_template * template)
{

	int i;
	int elem_num;
	TEMPLATE_ELEM * curr_elem;
	
	elem_num=template->elem_num;

	for(i=0;i<elem_num;i++)
	{
		curr_elem=&(template->elem_list[i]);	
		if(curr_elem->elem_desc->type==OS210_TYPE_ENDDATA)
			return NULL;
		if(!strcmp(name,curr_elem->elem_desc->name))
		{
			if(curr_elem->elem_desc->type != OS210_TYPE_ORGCHAIN)
				curr_elem->elem_var=template->var_list+i*sizeof(void *);
			return curr_elem;
		}
	}
	return NULL;	
}

void * read_elem_addr_with_mark(char * name, struct struct_template * template)
{

	int i,j;
	char elemname[MAX_NAME_LEN];
	char * subname[MAX_NAME_DEPTH];	
	int namedepth=0;
	int depth=0;
	struct struct_template * curr_template;
	TEMPLATE_ELEM * curr_elem;
	
	if(name ==NULL)
		return -EINVAL;
	if(template ==NULL)
		return -EINVAL;

	strncpy(elemname,name,MAX_NAME_LEN);
	namedepth = splitname(elemname,subname);
	if(namedepth<0)
		return namedepth;

	curr_template = template;
	curr_elem=NULL;
	
	for(depth=0;depth<=namedepth;depth++)
	{
		i=0;
		if(!strcmp("/",subname[depth]))
		{
			curr_template=get_root_template(curr_template);
		}
		else if(!strcmp("<",subname[depth]))
		{
			curr_template=curr_template->parent_struct;
		}
		else
		{
			curr_elem=get_elem_by_name_with_mark(subname[depth],curr_template);
			if(depth==namedepth)
				break;
			if(curr_elem->elem_desc->type!=OS210_TYPE_ORGCHAIN)
				return NULL;
			curr_template=(struct struct_template *)(curr_elem->elem_var);
			
		}

		if((curr_template == NULL) ||IS_ERR(curr_template))
				return curr_template;
	}
	return (void * )curr_elem;	
}

void * read_elem_addr(char * name, void * template)
{

	int i,j;
	char elemname[MAX_NAME_LEN];
	char * subname[MAX_NAME_DEPTH];	
	int namedepth=0;
	int depth=0;
	struct struct_template * curr_template;
	TEMPLATE_ELEM * curr_elem;
	
	if(name ==NULL)
		return -EINVAL;
	if(template ==NULL)
		return -EINVAL;

	strncpy(elemname,name,MAX_NAME_LEN);
	namedepth = splitname(elemname,subname);
	if(namedepth<0)
		return namedepth;

	curr_template = template;
	curr_elem=NULL;
	
	for(depth=0;depth<=namedepth;depth++)
	{
		i=0;
		if(!strcmp("/",subname[depth]))
		{
			curr_template=get_root_template(curr_template);
		}
		else if(!strcmp("<",subname[depth]))
		{
			curr_template=curr_template->parent_struct;
		}
		else
		{
			curr_elem=get_elem_by_name(subname[depth],curr_template);
			if(depth==namedepth)
				break;
			if(curr_elem->elem_desc->type!=OS210_TYPE_ORGCHAIN)
				return NULL;
			curr_template=(struct struct_template *)(curr_elem->elem_var);
			
		}

		if((curr_template == NULL) ||IS_ERR(curr_template))
				return curr_template;
	}
	return (void * )curr_elem;	
}


void free_struct_template(void * struct_template)
{
	struct struct_template * template;
	void * struct_array;
	struct struct_template * *currsub, * * nextsub;
	int i,j;
	int substruct_num;

	template=(struct struct_template * )struct_template;
	if(template == NULL)
		return;

	// struct_array is used	to record a special layer's substruct and switch the different layer's struct
	struct_array =kmalloc(sizeof(void *)*MAX_ARRAY_ELEM_NUM*2,GFP_KERNEL);

	if(struct_array==NULL)
		return -ENOMEM;

	memset(struct_array,0,sizeof(void *)*MAX_ARRAY_ELEM_NUM*2);

	currsub=(struct struct_template * *)struct_array;
	nextsub=(struct struct_template * *)struct_array+MAX_ARRAY_ELEM_NUM;
	currsub[0]=template;

	substruct_num=0;
	while(currsub[0] != NULL)
	{
		i=0;
		while(currsub[i]!=NULL)
		{
			for(j=0;j<currsub[i]->elem_num;j++)
			{
				if(currsub[i]->elem_list[j].elem_desc->type == OS210_TYPE_ORGCHAIN)
				{
					nextsub[substruct_num]=(struct struct_template *)(currsub[i]->elem_list[j].elem_var);
					if(nextsub[substruct_num]!=NULL)
						substruct_num++;
				} 
			}
			kfree(currsub[i]->var_list);
			kfree(currsub[i]);
			i++;

		}
	
		// step 3.2 :  switch the currsub and the next sub,then empty the next sub array
		struct struct_template * * tempsub;
		tempsub=currsub;
		currsub=nextsub;
		nextsub=tempsub;
		memset(nextsub,0,sizeof(struct struct_elem_attr *)*MAX_ARRAY_ELEM_NUM);
		substruct_num=0;
	}	
	kfree(struct_array);

	return;

}


void * create_struct_template(struct struct_elem_attr * struct_desc)
{
	struct struct_template * root_template;  // this is the basic struct template
	struct struct_template * curr_template;  // this is the template that we deal with now.


	int i=0,j=0;
	int struct_elem_num;

	struct struct_elem_attr * clone_desc;
	struct struct_elem_attr * curr_elem;
	struct struct_elem_attr * curr_desc;

//	TEMPLATE_ELEM * clone_elem;


	void * struct_array;
	struct struct_template * *currsub, * * nextsub;

	// struct_array is used	to record a special layer's substruct and switch the different layer's struct
	struct_array =kmalloc(sizeof(void *)*MAX_ARRAY_ELEM_NUM*2,GFP_KERNEL);

	if(struct_array==NULL)
		return -ENOMEM;

	memset(struct_array,0,sizeof(void *)*MAX_ARRAY_ELEM_NUM*2);

	currsub=(struct struct_template * *)struct_array;
	nextsub=(struct struct_template * *)struct_array+MAX_ARRAY_ELEM_NUM;


        // we use multi-times flush to get the size of all the sub struct with ping_pong mode
	// each time, begin with the first 


	
	// step 1: build the basic struct and assign its value to the currsub[0];

	// malloc the basic struct template and init it;
	root_template = struct_template_init(struct_desc);

	
	if(IS_ERR(root_template))
		return root_template;


	currsub[0]=root_template;


	// step 2: circled to deal with all the substructs,alloc them  and make relationship between them.
	

	int substruct_num=0;
	int temp_desc;

	while(currsub[0] != NULL)  // there is at least one struct not checked
	{
		// step 2.1 :  look through the struct,record all the  substruct element in the nextsub array

		i=0;
		while(currsub[i]!=NULL)
		{
			curr_desc=((struct struct_template *)currsub[i])->struct_desc;
			curr_elem=curr_desc;
			j=0;

			// look through all the elem in the struct 
			while((curr_elem->type != OS210_TYPE_ENDDATA)&&(curr_elem->name !=NULL))
			{
					// we find a substruct
				if(curr_elem->type == OS210_TYPE_ORGCHAIN)
				{
					// malloc this substruct's template and init it;
					curr_template = struct_template_init((struct struct_emem_attr *)(curr_elem->attr));

					if(IS_ERR(curr_template))
					{
						kfree(struct_array);
						return -ENOMEM;
					}
					
	
					// assign this substruct template to the struct template's elem list
					currsub[i]->elem_list[j].elem_var=curr_template;

					// let substruct template's parent struct be currsub[i];
					curr_template->parent_struct=currsub[i];

					// record the substruct template to the nextsub template array
					nextsub[substruct_num++]=curr_template;
				} 
	
				j++;
				curr_elem=curr_desc+j;
				if(j>=MAX_ARRAY_ELEM_NUM)
				{
					kfree(struct_array);
					return -EINVAL;
				}
			}
			i++;
		}


		if(nextsub[0]==NULL)
			break;
		// giva a NULL as nextsub array's tail
		nextsub[substruct_num]=NULL;

	
		// step 2.2 :  switch the currsub and the next sub,then empty the next sub array
		struct struct_template * * tempsub;
		tempsub=currsub;
		currsub=nextsub;
		nextsub=tempsub;
	//	memset(nextsub,0,sizeof(struct struct_elem_attr *)*MAX_ARRAY_ELEM_NUM);
		substruct_num=0;

	}

	// step 3: circled to deal with all the substructs again, make relation of all the extern defined elem and the defined size.
	// define_size data elem(data elem)'s attribute elem will be a point to the elem which defines the data's length(length elem),
	// and the length elem 's attribute elem will be a pointer to an length integer.
	

	memset(struct_array,0,sizeof(void *)*MAX_ARRAY_ELEM_NUM*2);
	currsub=(struct struct_template * *)struct_array;
	nextsub=(struct struct_template * *)struct_array+MAX_ARRAY_ELEM_NUM;
	currsub[0]=root_template;
	substruct_num=0;


	TEMPLATE_ELEM * elem_list; 
	while(currsub[0] != NULL)  // there is at least one struct not checked
	{

		i=0;
		while(currsub[i]!=NULL)
		{
		// step 3.1 :  look throught the struct,record all the  substruct element in the nextsub array
			elem_list=currsub[i]->elem_list;
			for(j=0;j<currsub[i]->elem_num;j++)
			{
				if(elem_list[j].elem_desc->type == OS210_TYPE_ORGCHAIN)
				{
					nextsub[substruct_num++]=(struct struct_template *)(elem_list[j].elem_var);
				} 
				else if((elem_list[j].elem_desc->type == OS210_TYPE_DEFINE)|| 
					(elem_list[j].elem_desc->type == OS210_TYPE_DEFSTR)||
					(elem_list[j].elem_desc->type == OS210_TYPE_DEFSTRARRAY))
				{
					TEMPLATE_ELEM * curr_elem;
					curr_elem = read_elem_addr_with_mark((char *)elem_list[j].elem_desc->attr,currsub[i]);
					if((curr_elem==NULL)|| IS_ERR(curr_elem))
						return curr_elem;
					elem_list[j].elem_var=(void *)curr_elem;
					*(int *) (curr_elem->elem_var) = 0;
				}
			}
			i++;

		}
	
		// step 3.2 :  switch the currsub and the next sub,then empty the next sub array
		struct struct_template * * tempsub;
		tempsub=currsub;
		currsub=nextsub;
		nextsub=tempsub;
		memset(nextsub,0,sizeof(struct struct_elem_attr *)*MAX_ARRAY_ELEM_NUM);
		substruct_num=0;


	}

	// free the temp struct array
	kfree(struct_array);
	return 	root_template;
}
/*
void * __create_struct_template(struct struct_elem_attr * struct_desc)
{
	struct struct_template * root_template;
	struct struct_template * curr_template;
	int i=0;j=0;
	int struct_elem_num;
	struct struct_elem_attr * clone_desc;
	struct struct_elem_attr * curr_elem;
	struct struct_elem_attr * curr_desc;

	void * stack;
	int addroffset;
	int offset;
	int i;
	int value;
	int retval;
	BYTE * addr;

	TEMPLATE_ELEM * struct_elem;
	// use a pointer stack to finish the throughout of the template
	stack=init_pointer_stack(MAX_NAME_DEPTH);
	
	if(IS_ERR(stack))
		return stack;

	struct deal_context
	{
		int elem_num;
		int elem_no;
		struct parent_struct_template;
		struct struct_elem_attr * curr_desc;
		struct curr_struct_template;
	} * saved_context;


	root_template= struct_template_init(struct_desc);
	if((root_template==NULL) || IS_ERR(root_template))
		return root_template;

	curr_template=root_template;

	saved_context=kmalloc(sizeof(struct deal_context));
	if(saved_context==NULL)
		return -ENOMEM;
	saved_context->elem_num=root_template->elem_num;
	saved_context->elem_no=0;
	saved_context->parent_struct_template=NULL;
	saved_context->curr_struct_template=root_template;
	saved_context->curr_desc=struct_desc;
	

	while(saved_context->elem_no<saved_context->elem_num)
	{
		struct_elem=e
			

	}
	for(i=0;
	while


	struct_template=(struct struct_template *)template;
	curr_struct = struct_template;
	
	i=0;
	// get the first elem
	struct_elem=curr_struct->elem_list;
	addroffset=0;
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

		//  compute the addr's size 
		if((offset=struct_get_elem_size(struct_elem))<0)
		{
			free_pointer_stack(stack);
			return offset;
		}
		addroffset+=offset;
		struct_elem++;
	}
	free_pointer_stack(stack);
	*struct_addr=kmalloc(addroffset,GFP_KERNEL);
	if(*struct_addr == NULL)
		return -ENOMEM;
	return addroffset;
}
*/
int free_struct_elem(void * addr,struct struct_elem_attr * elem_attr)
{
	V_String * vstring;
	void * datapointer;

	switch(elem_attr->type) {
		case OS210_TYPE_STRING :
			return elem_attr->size;
		case OS210_TYPE_INT :
		case OS210_TYPE_ENUM :
		case OS210_TYPE_FLAG :
		case TPM_TYPE_UINT32 :
		case OS210_TYPE_TIME :
		case ASN_TYPE_INT:
			return sizeof(int);
		case OS210_TYPE_UCHAR :
			return sizeof(unsigned char);
		case OS210_TYPE_USHORT :
		case TPM_TYPE_UINT16 :
			return sizeof(unsigned short);
		case OS210_TYPE_LONGLONG:
		case TPM_TYPE_UINT64 :
			return sizeof(long long);
		case OS210_TYPE_BINDATA:
		case OS210_TYPE_BITMAP:
		case OS210_TYPE_HEXDATA:
			return elem_attr->size;
		case OS210_TYPE_BINARRAY:
			return  elem_attr->size*(int)(elem_attr->attr);
		case OS210_TYPE_VSTRING:
			vstring = (V_String *)addr;
			kfree(vstring->String);
			return sizeof(V_String);
		case OS210_TYPE_ESTRING:
		case OS210_TYPE_JSONSTRING:
			if(addr!=NULL)
				kfree(addr);
			return sizeof(char *);
		case OS210_TYPE_NODATA:
		case OS210_TYPE_DEFINE:
		case OS210_TYPE_DEFSTR:
		case OS210_TYPE_DEFSTRARRAY:
			datapointer=*(BYTE **)addr;
			kfree(datapointer);
			return sizeof(void *);
		case ASN_TYPE_OIDSTRING:
		case ASN_TYPE_OID:
		case ASN_TYPE_LONGINT:
			kfree(addr);
			return sizeof(void *);
		case ASN_TYPE_SEQUENCE:
		case ASN_TYPE_SET:
		case ASN_TYPE_CHOICE:
			kfree(addr);
			return sizeof(void *);
		case ASN_TYPE_TIME:
			return elem_attr->size;
		case OS210_TYPE_ORGCHAIN:
		default:
			return -EINVAL;
	}
	return 0;
}

int struct_get_int_value(void * addr,TEMPLATE_ELEM * elem_template)
{

   struct struct_elem_attr * elem_attr;	
   const int bufsize=40;
   BYTE buf[bufsize];
   int retval;
   int int_value;
   unsigned char char_value;
   unsigned short short_value;
   long long long_long_value;
   int i,j;
   BYTE * data;
   V_String * vstring;

   retval=0;
   elem_attr=elem_template->elem_desc;
   switch(elem_attr->type) {
#ifdef USER_MODE
	case OS210_TYPE_STRING :
		if(elem_attr->size>bufsize)
			return -EINVAL;
		retval=atoi(addr);
		break;
#endif
	case OS210_TYPE_INT :
	case OS210_TYPE_ENUM :
	case OS210_TYPE_FLAG :
	case TPM_TYPE_UINT32 :
  		retval=*(int *)addr;
		break;
	case OS210_TYPE_TIME :
  		return -EINVAL;
	case OS210_TYPE_UCHAR :
  		retval=*(BYTE *)addr;
		break;
	case OS210_TYPE_USHORT :
	case TPM_TYPE_UINT16 :
  		retval=*(UINT16 *)addr;
		break;
	case OS210_TYPE_LONGLONG:
	case TPM_TYPE_UINT64 :
		long_long_value=*(long long *)addr;
		if((long_long_value>65535) || (long_long_value <0))
			return -EINVAL;
  		retval=long_long_value;
	case OS210_TYPE_BINDATA:
	case OS210_TYPE_BITMAP:
	case OS210_TYPE_HEXDATA:
	case OS210_TYPE_BINARRAY:
			return -EINVAL;
#ifdef USER_MODE
	case OS210_TYPE_VSTRING:
		vstring = (V_String *)addr;
		if((vstring->length <0) || vstring->length> bufsize)
		{
			retval=-EINVAL;	
		}
		retval=atoi(addr);
		break;
	case OS210_TYPE_ESTRING:
	case OS210_TYPE_JSONSTRING:
		{
			if(addr==NULL)
				return -EINVAL;
			int length=strlen((char *)addr);
			if((length <0) || (length> bufsize))
				retval=-EINVAL;	
			retval=atoi((char *)addr);
		}
		break;
#endif

	case OS210_TYPE_DEFINE:
	case OS210_TYPE_DEFSTR:
	case OS210_TYPE_DEFSTRARRAY:
	case OS210_TYPE_ORGCHAIN:
	case OS210_TYPE_NODATA:
	default:
		return -EINVAL;
	}
	if((retval <0) || retval> 65535)
		return -EINVAL;
 	return retval;
}

int struct_get_elem_size(TEMPLATE_ELEM * struct_elem)
{
	struct struct_elem_attr * elem_attr;
	elem_attr= struct_elem->elem_desc;
	switch(elem_attr->type) {
		case OS210_TYPE_STRING :
			return elem_attr->size;
		case OS210_TYPE_INT :
		case OS210_TYPE_ENUM :
		case OS210_TYPE_FLAG :
		case TPM_TYPE_UINT32 :
		case ASN_TYPE_INT:
			return sizeof(int);
		case OS210_TYPE_TIME:
  			return sizeof(time_t);
		case OS210_TYPE_UCHAR :
			return sizeof(unsigned char);
		case OS210_TYPE_USHORT :
		case TPM_TYPE_UINT16 :
			return sizeof(unsigned short);
		case OS210_TYPE_LONGLONG:
		case TPM_TYPE_UINT64 :
			return sizeof(long long);
		case OS210_TYPE_BINDATA:
			return elem_attr->size;
		case OS210_TYPE_BITMAP:
		case OS210_TYPE_HEXDATA:
			return elem_attr->size;
		case OS210_TYPE_BINARRAY:
			return elem_attr->size*(int)(elem_attr->attr);
		case OS210_TYPE_VSTRING:
			return sizeof(V_String);
		case OS210_TYPE_ESTRING:
		case OS210_TYPE_JSONSTRING:
			return sizeof(char *);
		case OS210_TYPE_NODATA:
			return elem_attr->size;
		case OS210_TYPE_DEFINE:
		case OS210_TYPE_DEFSTR:
		case OS210_TYPE_DEFSTRARRAY:
		case ASN_TYPE_OIDSTRING:
		case ASN_TYPE_OID:
		case ASN_TYPE_LONGINT:
			return sizeof(void *);
		case ASN_TYPE_SEQUENCE:
		case ASN_TYPE_SET:
		case ASN_TYPE_CHOICE:
			return sizeof(void *);
		case ASN_TYPE_TIME:
			return elem_attr->size;
		case OS210_TYPE_ORGCHAIN:
		default:
			break;
	}
	return 0;
}

typedef struct tagpointer_stack
{
	void ** top;
	void ** curr; 
	int size;
}POINTER_STACK;

void * init_pointer_stack(int size)
{
	POINTER_STACK * stack;
	BYTE * buffer;
	buffer=kmalloc(sizeof(POINTER_STACK)+sizeof(void *)*size,GFP_KERNEL);
	if(buffer==NULL)
		return -ENOMEM;
	stack=(POINTER_STACK *)buffer;
	stack->top=(void **)(buffer+sizeof(POINTER_STACK));
	stack->curr=stack->top;
	stack->size=size;
	return stack;
}
void free_pointer_stack(void * stack)
{	
	kfree(stack);
	return;
}

int pointer_stack_push(void * pointer_stack,void * pointer)
{
	POINTER_STACK * stack;
	stack=(POINTER_STACK *)pointer_stack;
	if(stack->curr+1>=stack->top+stack->size)
		return -ENOSPC;
	*(stack->curr)=pointer;
	stack->curr++;
	return 0;
}


void * pointer_stack_pop(void * pointer_stack)
{
	POINTER_STACK * stack;
	stack=(POINTER_STACK *)pointer_stack;
	if(--stack->curr<stack->top)
		return -ERANGE;
	return *(stack->curr);
}

typedef struct tagpointer_queue
{
	void ** buffer;
	int size;
	int head;
	int tail;
}POINTER_QUEUE;

void * init_pointer_queue(int size)
{
	POINTER_QUEUE * queue;
	BYTE * buffer;
	buffer=kmalloc(sizeof(POINTER_QUEUE)+sizeof(void *)*size,GFP_KERNEL);
	if(buffer==NULL)
		return -ENOMEM;
	queue=(POINTER_QUEUE *)buffer;
	memset(queue,0,sizeof(POINTER_QUEUE)+sizeof(void *)*size);
	queue->buffer=(void **)(buffer+sizeof(POINTER_QUEUE));
	queue->size=size;
	queue->head=-1;
	return queue;
}
void free_pointer_queue(void * queue)
{	
	kfree(queue);
	return;
}

int pointer_queue_put(void * pointer_queue,void * pointer)
{
	POINTER_QUEUE * queue;
	queue=(POINTER_QUEUE *)pointer_queue;
	if(queue->head==-1)
		queue->head=0;
	else if(queue->head ==queue->size-1)
	{
		if(queue->tail==0)
			return -ENOSPC;
		queue->head=0;
	}
	else
	{
		if(queue->head+1==queue->tail)
			return -ENOSPC;
		queue->head++;
	}
	queue->buffer[queue->head]=pointer;
	return 0;
}


int pointer_queue_get(void * pointer_queue,void **pointer)
{
	POINTER_QUEUE * queue;
	queue=(POINTER_QUEUE *)pointer_queue;
	if(queue->head==-1)
		return -EINVAL;
	*pointer=queue->buffer[queue->tail];
	if(queue->tail==queue->head)
	{
		queue->head=-1;
		queue->tail=0;
		return 0;
	}
	if(queue->tail ==queue->size-1)
		queue->tail=0;
	else
		queue->tail++;
	return 0;
}

int struct_get_size(void * template)
{
	struct struct_template * struct_template;
	struct struct_template * curr_struct;
	void * stack;
	int addroffset;
	int offset;
	int i;
	int value;
	int retval;
	BYTE * addr;

	TEMPLATE_ELEM * struct_elem;
	// use a pointer stack to finish the throughout of the template
	stack=init_pointer_stack(MAX_NAME_DEPTH);
	
	if(IS_ERR(stack))
		return stack;

	struct_template=(struct struct_template *)template;
	curr_struct = struct_template;
	
	i=0;
	// get the first elem
	struct_elem=curr_struct->elem_list;
	addroffset=0;
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

		//  compute the addr's size 
		if((offset=struct_get_elem_size(struct_elem))<0)
		{
			free_pointer_stack(stack);
			return offset;
		}
		addroffset+=offset;
		struct_elem++;
	}
	free_pointer_stack(stack);
	return addroffset;
}

int alloc_struct(void ** struct_addr, void * template)
{
	struct struct_template * struct_template;
	struct struct_template * curr_struct;
	void * stack;
	int addroffset;
	int offset;
	int i;
	int value;
	int retval;
	BYTE * addr;

	TEMPLATE_ELEM * struct_elem;
	// use a pointer stack to finish the throughout of the template
	stack=init_pointer_stack(MAX_NAME_DEPTH);
	
	if(IS_ERR(stack))
		return stack;

	struct_template=(struct struct_template *)template;
	curr_struct = struct_template;
	
	i=0;
	// get the first elem
	struct_elem=curr_struct->elem_list;
	addroffset=0;
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

		//  compute the addr's size 
		if((offset=struct_get_elem_size(struct_elem))<0)
		{
			free_pointer_stack(stack);
			return offset;
		}
		addroffset+=offset;
		struct_elem++;
	}
	free_pointer_stack(stack);
	*struct_addr=kmalloc(addroffset,GFP_KERNEL);
	if(*struct_addr == NULL)
		return -ENOMEM;
	return addroffset;
}

int free_struct(void * struct_addr, void * template)
{
	struct struct_template * struct_template;
	struct struct_template * curr_struct;
	void * stack;
	int addroffset;
	int offset;
	int i;
	int value;
	int retval;

	TEMPLATE_ELEM * struct_elem;
	// use a pointer stack to finish the throughout of the template
	stack=init_pointer_stack(MAX_NAME_DEPTH);
	
	if(IS_ERR(stack))
		return stack;

	struct_template=(struct struct_template *)template;
	curr_struct = struct_template;
	
	i=0;
	// get the first elem
	struct_elem=curr_struct->elem_list;
	addroffset=0;
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

		//  compute the addr's size 
		if((offset=free_struct_elem(struct_addr+addroffset,struct_elem))<0)
		{
			return offset;
		}
		addroffset+=offset;
		struct_elem++;
	}
	free_pointer_stack(stack);
	kfree(struct_addr);
	return 0;
}

int struct_2_struct_comp_elem(void * addr,void * elem_data,TEMPLATE_ELEM * elem_template)
{

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
   int comp_result;
   int elem_size;	

   retval=0;
   elem_attr=elem_template->elem_desc;
   switch(elem_attr->type) {
	case OS210_TYPE_STRING :
		comp_result=strncmp(addr,elem_data,elem_attr->size);
		if(comp_result==0)
			retval=1;
		else
			retval=0;
		break;
	case OS210_TYPE_INT :
	case OS210_TYPE_ENUM :
	case OS210_TYPE_FLAG :
	case TPM_TYPE_UINT32 :
		if(*(int *)addr == *(int *)elem_data) 
			retval=1;
		else
			retval=0;
		break;
	case OS210_TYPE_TIME :
		comp_result=memcmp(elem_data,addr,sizeof(time_t));
		if(comp_result==0)
			retval=1;
		else
			retval=0;
		break;
	case OS210_TYPE_UCHAR :
		if(*(char *)addr == *(char *)elem_data) 
			retval=1;
		else
			retval=0;
		break;
	case OS210_TYPE_USHORT :
	case TPM_TYPE_UINT16 :
		if(*(short *)addr == *(short *)elem_data) 
			retval=1;
		else
			retval=0;
		break;
	case OS210_TYPE_LONGLONG:
	case TPM_TYPE_UINT64 :
		if(*(long long *)addr == *(long long *)elem_data) 
			retval=1;
		else
			retval=0;
		break;
	case OS210_TYPE_BINDATA:
	case OS210_TYPE_BITMAP:
	case OS210_TYPE_HEXDATA:
		comp_result=memcmp(addr,elem_data,elem_attr->size);
		if(comp_result==0)
			retval=1;
		else
			retval=0;
		break;
	case OS210_TYPE_BINARRAY:
  		elem_size=elem_attr->size*(int)(elem_attr->attr);
		comp_result=memcmp(addr,elem_data,elem_size);
		if(comp_result==0)
			retval=1;
		else
			retval=0;
		break;
	case OS210_TYPE_VSTRING:
		{
			vstring = (V_String *)addr;
			V_String * dest_vstring = (V_String *)elem_data;
			if((vstring->length <0) || vstring->length> OS210_MAX_BUF)
			{
				retval=-EINVAL;	
			}
			if(vstring->length!=dest_vstring->length)
			{
				retval=0;
				break;
			}
			comp_result=strncmp(vstring->String,dest_vstring->String,vstring->length);
			if(comp_result==0)
				retval=1;
			else
				retval=0;
		}
		break;
	case OS210_TYPE_ESTRING:
	case OS210_TYPE_JSONSTRING:
		{
			char * estring;
			char * dest_estring;
			estring=*(char **)addr;
			dest_estring=*(char **)elem_data;
			// if the string is an empty string
			if((estring==NULL)||(dest_estring==NULL))
			{
				retval=0;
			}
			else
			{

				elem_size=strlen(estring);
				if(elem_size<0) 
					retval=-EINVAL;	
				comp_result=strncmp(estring,dest_estring,elem_size);
				if(comp_result==0)
					retval=1;
				else
					retval=0;
			}
		}
		break;


	case OS210_TYPE_DEFINE:
	case OS210_TYPE_DEFSTR:
		elem_define=(TEMPLATE_ELEM *)(elem_template->elem_var);
		define_value=*(int *)elem_define->elem_var;
		if(define_value<0)
			return -EINVAL;
		if(define_value>32768)
			return -EINVAL;
		elem_size=elem_attr->size*define_value;

		comp_result=strncmp(*(char **)addr,*(char **)elem_data,elem_size);
		if(comp_result==0)
			retval=1;
		else
			retval=0;
		strncmp(*(char **)elem_data,*(char **)addr,elem_attr->size*define_value);
//		for(i=0;i<define_value;i++)
//			memcpy(elem_data+i*elem_attr->size,*(char **)addr+i*sizeof(char *),elem_attr->size);
		break;
	case OS210_TYPE_DEFSTRARRAY:
		{
			retval=0;
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
int struct_2_blob_write_elem(void * addr,void * elem_data,TEMPLATE_ELEM * elem_template)
{

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
   int define_value;;

   retval=0;
   elem_attr=elem_template->elem_desc;
   switch(elem_attr->type) {
	case OS210_TYPE_STRING :
  		retval=elem_attr->size;
		memset(elem_data,0,sizeof(elem_attr->size));
		strncpy(elem_data,addr,retval);
		break;
	case OS210_TYPE_INT :
	case OS210_TYPE_ENUM :
	case OS210_TYPE_FLAG :
  		retval=sizeof(int);
		memcpy(elem_data,addr,retval);
		break;
	case TPM_TYPE_UINT32 :
  		retval=sizeof(int);
		UINT32ToArray(*(int *)addr,elem_data);
		break;
	case OS210_TYPE_TIME :
  		retval=sizeof(time_t);
		memcpy(elem_data,addr,retval);
		break;
	case OS210_TYPE_UCHAR :
  		retval=sizeof(unsigned char);
		memcpy(elem_data,addr,retval);
		break;
	case OS210_TYPE_USHORT :
  		retval=sizeof(unsigned short);
		memcpy(elem_data,addr,retval);
		break;
	case TPM_TYPE_UINT16 :
  		retval=sizeof(UINT16);
		UINT16ToArray(*(int *)addr,elem_data);
		break;
	case OS210_TYPE_LONGLONG:
  		retval=sizeof(long long);
		memcpy(elem_data,addr,retval);
		break;
	case TPM_TYPE_UINT64 :
  		retval=sizeof(UINT64);
		UINT64ToArray(*(int *)addr,elem_data);
		break;
	case OS210_TYPE_BINDATA:
	case OS210_TYPE_BITMAP:
	case OS210_TYPE_HEXDATA:
  		retval=elem_attr->size;
		memcpy(elem_data,addr,retval);
		break;
	case OS210_TYPE_BINARRAY:
  		retval=elem_attr->size*(int)(elem_attr->attr);
		memcpy(elem_data,addr,retval);
		break;
	case OS210_TYPE_VSTRING:
		vstring = (V_String *)addr;
		if((vstring->length <0) || vstring->length> OS210_MAX_BUF)
		{
			retval=-EINVAL;	
		}
		short_value=vstring->length;
		memcpy(elem_data,&(short_value),sizeof(UINT16));
		memcpy(elem_data+sizeof(UINT16),vstring->String,vstring->length);
		retval=sizeof(UINT16)+vstring->length;
		break;
	case OS210_TYPE_ESTRING:
	case OS210_TYPE_JSONSTRING:
		{
			char * estring;
			estring=*(char **)addr;
			// if the string is an empty string
			if(estring==NULL)
			{
				retval=1;
				memset(elem_data,0,retval);
			}
			else
			{

				retval=strlen(estring);
				if(retval<0) 
					retval=-EINVAL;	
				if((elem_attr->size!=0) && (retval>elem_attr->size))
					retval=-EINVAL;	
				retval++;
				memcpy(elem_data,estring,retval);
			}
		}
		break;


	case OS210_TYPE_DEFINE:
	case OS210_TYPE_DEFSTR:
		elem_define=(TEMPLATE_ELEM *)(elem_template->elem_var);
		define_value=*(int *)elem_define->elem_var;
		if(define_value<0)
			return -EINVAL;
		if(define_value>32768)
			return -EINVAL;
		retval=elem_attr->size*define_value;
		
		memcpy(elem_data,*(char **)addr,elem_attr->size*define_value);
		break;
	case OS210_TYPE_DEFSTRARRAY:
		elem_define=(TEMPLATE_ELEM *)(elem_template->elem_var);
		define_value=*(int *)elem_define->elem_var;
		if(define_value<0)
			return -EINVAL;
		if(define_value>32768)
			return -EINVAL;
		retval=elem_attr->size*define_value;
		
		memcpy(elem_data,*(char **)addr,define_value*elem_attr->size);
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


int struct_2_blob(void * addr, void * blob,void * template)
{
	struct struct_template * struct_template;
	struct struct_template * curr_struct;
	void * stack;
	int bloboffset=0;
	int addroffset=0;
	int i;
	int value;
	int * define_value;
	int retval;

	TEMPLATE_ELEM * struct_elem;
	// use a pointer stack to finish the throughout of the template
	stack=init_pointer_stack(MAX_NAME_DEPTH);
	
	if(IS_ERR(stack))
		return stack;

	struct_template=(struct struct_template *)template;
	curr_struct = struct_template;
	
	i=0;
	// get the first elem
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

		// if this elem's elem_var is not empty, then it is a defining elem,we should get its value for later use
		switch(struct_elem->elem_desc->type)
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
				if(struct_elem->elem_var != 0)
				{	
					define_value = (int *)(struct_elem->elem_var);
					*define_value = struct_get_int_value(addr+addroffset,struct_elem); 
				}
			default:
				break;
		}
		//  write struct value to blob
		retval = struct_2_blob_write_elem(addr+addroffset,blob+bloboffset,struct_elem);
		if(retval<0)
		{
			free_pointer_stack(stack);
			return retval;
		}
		bloboffset+=retval;
		addroffset+=struct_get_elem_size(struct_elem);
		struct_elem++;
	}
	free_pointer_stack(stack);
	return bloboffset;
}

int struct_2_part_blob(void * addr, void * blob,void * template,char * name_list)
{
	struct struct_template * struct_template;
	struct struct_template * curr_struct;
	void * stack;
	int bloboffset=0;
	int addroffset=0;
	int i;
	int value;
	int * define_value;
	int retval;
	char current_name[256];
	char * compare_name[64];
	char * clone_list;
	int offset=0;
	int namestart=0;

	TEMPLATE_ELEM * struct_elem;
	// use a pointer stack to finish the throughout of the template
	stack=init_pointer_stack(MAX_NAME_DEPTH);
	
	if(IS_ERR(stack))
		return stack;
	
	clone_list=kmalloc(strlen(name_list)+1,GFP_KERNEL);
	if(clone_list==NULL)
		return -ENOMEM;
	memset(compare_name,0,sizeof(char *)*64);
	memset(current_name,0,256);
	memcpy(clone_list,name_list,strlen(name_list)+1);


	i=0;
	offset=0;
	namestart=0;
	while(clone_list[offset]!=0)
	{
		if(IsAValidChar(clone_list[offset]))
		{
			if((clone_list[offset]==' ')||(clone_list[offset]==',')||(clone_list[offset]==';'))
			{
				clone_list[offset++]=0;
				namestart=0;
				continue;
			}
		}
		else
		{
				clone_list[offset++]=0;
				namestart=0;
				continue;

		}

		if(namestart==0)
		{
			compare_name[i++]=clone_list+offset;
		}
		offset++;
		namestart++;

	}
	


	struct_template=(struct struct_template *)template;
	curr_struct = struct_template;
	
	i=0;
	// get the first elem
	struct_elem=curr_struct->elem_list;
	while(1){
		// if this elem is out of the elemlist's range, then we should pop a pointer of the stack
		if(struct_elem >= curr_struct->elem_list+curr_struct->elem_num-1)
		{
			struct_elem = pointer_stack_pop(stack);
			// if pop failed, it means curr_struct is the root struct template, and we finish the throughout. 

			if(struct_elem==-ERANGE)
				break;
			//  else, we changes the curr_struct;
			curr_struct=struct_elem->elem_struct;
			for(i=strlen(current_name)-1;i>0;i--)
			{
				if(current_name[i]=='.')
				{
					current_name[i]=0;
					break;
				}
			}
			if(i==0)
				current_name[i]=0;
		}


		// if this elem is a substruct, push the next elem in this struct, then get the first elem of the substruct as the curr struct_elem; 
		while(struct_elem->elem_desc->type == OS210_TYPE_ORGCHAIN)
		{
			pointer_stack_push(stack,struct_elem+1);
			curr_struct=(struct struct_template *)(struct_elem->elem_var);
			struct_elem=curr_struct->elem_list;	
			if(current_name[i]==0)
			{
				strcpy(current_name,struct_elem->elem_desc->name);
			}
			else
			{
				strcat(current_name,".");
				strcat(current_name,struct_elem->elem_desc->name);
			}
		}	

		// if this elem's elem_var is not empty, then it is a defining elem,we should get its value for later use
		switch(struct_elem->elem_desc->type)
		{
			case OS210_TYPE_INT:
			case OS210_TYPE_UCHAR:
			case OS210_TYPE_USHORT:
			case OS210_TYPE_LONGLONG:
			case OS210_TYPE_STRING:
			case OS210_TYPE_ESTRING:
			case OS210_TYPE_JSONSTRING:
			case OS210_TYPE_VSTRING:

		// if this elem's elem_var is not empty, then it is a defining elem,we should get its value for later use
				if(struct_elem->elem_var != 0)
				{	
					define_value = (int *)(struct_elem->elem_var);
					*define_value = struct_get_int_value(addr+addroffset,struct_elem); 
				}
			default:
				break;
		}
		//  write struct value to blob

		if(current_name[i]==0)
		{
			strcpy(current_name,struct_elem->elem_desc->name);
		}
		else
		{
			strcat(current_name,".");
			strcat(current_name,struct_elem->elem_desc->name);
		}

		i=0;
		while(compare_name[i]!=NULL)
		{
			if(strcmp(compare_name[i++],current_name)==0)
			{
				retval = struct_2_blob_write_elem(addr+addroffset,blob+bloboffset,struct_elem);
				if(retval<0)
				{
					free_pointer_stack(stack);
					return retval;
				}
				bloboffset+=retval;
			}
		}
		addroffset+=struct_get_elem_size(struct_elem);
		struct_elem++;

		for(i=strlen(current_name)-1;i>0;i--)
		{
			if(current_name[i]=='.')
			{
				current_name[i]=0;
				break;
			}
		}
		if(i==0)
			current_name[i]=0;
	}
	free_pointer_stack(stack);
	return bloboffset;
}

int blob_get_int_value(void * blob,TEMPLATE_ELEM * elem_template)
{

   struct struct_elem_attr * elem_attr;	
   const int bufsize=40;
   BYTE buf[bufsize];
   int retval;
   int int_value;
   unsigned char char_value;
   unsigned short short_value;
   long long long_long_value;
   int i,j;
   BYTE * data;
   V_String vstring;

   memset(buf,0,bufsize);
   retval=0;
   elem_attr=elem_template->elem_desc;
   switch(elem_attr->type) {
#ifdef USER_MODE
	case OS210_TYPE_STRING :
		if(elem_attr->size>bufsize)
			return -EINVAL;
		memcpy(buf,blob,elem_attr->size);
		retval=atoi(blob);
		break;
#endif
	case OS210_TYPE_INT :
	case OS210_TYPE_ENUM :
	case OS210_TYPE_FLAG :
  		retval=*(int *)blob;
		break;
	case TPM_TYPE_UINT32 :
  		retval=Decode_UINT32(blob);
		break;
	case OS210_TYPE_TIME :
  		return -EINVAL;
	case OS210_TYPE_UCHAR :
  		retval=*(BYTE *)blob;
		break;
	case OS210_TYPE_USHORT :
  		retval=*(UINT16 *)blob;
		break;
	case TPM_TYPE_UINT16 :
  		retval=Decode_UINT16(blob);
		break;
	case OS210_TYPE_LONGLONG:
		long_long_value=*(long long *)blob;
		if((long_long_value>65535) || (long_long_value <0))
			return -EINVAL;
		retval=long_long_value;
		break;
	case TPM_TYPE_UINT64 :
  		retval=Decode_UINT64(blob);
		break;
	case OS210_TYPE_BINDATA:
	case OS210_TYPE_BITMAP:
	case OS210_TYPE_HEXDATA:
	case OS210_TYPE_BINARRAY:
			return -EINVAL;
#ifdef USER_MODE
	case OS210_TYPE_VSTRING:
		vstring.length=*(UINT16 *)blob;
		if((vstring.length <0) || vstring.length> bufsize)
		{
			retval=-EINVAL;	
		}
		memcpy(buf,blob+sizeof(UINT16),vstring.length);
		retval=atoi(buf);
		break;
	case OS210_TYPE_ESTRING:
	case OS210_TYPE_JSONSTRING:
		{
			int length=strlen(blob);
			if((length <0) || (length> bufsize))
				retval=-EINVAL;	
			retval=atoi(blob);
		}
		break;
#endif

	case OS210_TYPE_DEFINE:
	case OS210_TYPE_DEFSTR:
	case OS210_TYPE_DEFSTRARRAY:
	case OS210_TYPE_ORGCHAIN:
	case OS210_TYPE_NODATA:
	default:
		return -EINVAL;
	}
	if((retval <0) || retval> 65535)
		return -EINVAL;
 	return retval;
}

int blob_2_struct_write_elem(void * elem_data,void * addr,TEMPLATE_ELEM * elem_template)
{

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
  		retval=elem_attr->size;
		strncpy(addr,elem_data,retval);
		break;
	case OS210_TYPE_INT :
	case OS210_TYPE_ENUM :
	case OS210_TYPE_FLAG :
  		retval=sizeof(int);
		memcpy(addr,elem_data,retval);
		break;
	case TPM_TYPE_UINT32 :
  		retval=sizeof(int);
  		*(int *)addr=Decode_UINT32(elem_data);
		break;
	case OS210_TYPE_TIME :
  		retval=sizeof(time_t);
		memcpy(addr,elem_data,retval);
		break;
	case OS210_TYPE_UCHAR :
  		retval=sizeof(unsigned char);
		memcpy(addr,elem_data,retval);
		break;
	case OS210_TYPE_USHORT :
  		retval=sizeof(unsigned short);
		memcpy(addr,elem_data,retval);
		break;
	case TPM_TYPE_UINT16 :
  		retval=sizeof(UINT16);
  		*(UINT16  *)addr=Decode_UINT16(elem_data);
		break;
	case OS210_TYPE_LONGLONG:
  		retval=sizeof(long long);
		memcpy(addr,elem_data,retval);
		break;
	case TPM_TYPE_UINT64 :
  		retval=sizeof(UINT64);
  		*(UINT64  *)addr=Decode_UINT64(elem_data);
		break;
	case OS210_TYPE_BINDATA:
	case OS210_TYPE_BITMAP:
	case OS210_TYPE_HEXDATA:
  		retval=elem_attr->size;
		memcpy(addr,elem_data,retval);
		break;
	case OS210_TYPE_BINARRAY:
  		retval=elem_attr->size*(int)(elem_attr->attr);
		memcpy(addr,elem_data,retval);
		break;
	case OS210_TYPE_VSTRING:
		memcpy(&short_value,elem_data,sizeof(UINT16));
		vstring = (V_String *)addr;
		vstring->length=(int)short_value;
		if((vstring->length <0) || vstring->length> OS210_MAX_BUF)
		{
			retval=-EINVAL;	
		}
		vstring->String=kmalloc(vstring->length,GFP_KERNEL);
		if(vstring->String==NULL)
			return -ENOMEM;
		memcpy(vstring->String,elem_data+sizeof(UINT16),vstring->length);
		retval=sizeof(UINT16)+vstring->length;
		break;
	case OS210_TYPE_ESTRING:
	case OS210_TYPE_JSONSTRING:
		{
			char * estring;
			retval=strlen(elem_data);
			if(retval<0)
				retval=-EINVAL;	
			if((elem_attr->size!=0) && (retval>elem_attr->size))
				retval=-EINVAL;	
			retval++;
			estring=kmalloc(retval,GFP_KERNEL);
			if(estring==NULL)
				return -ENOMEM;
			memcpy(estring,elem_data,retval);
			*(char **)addr=estring;
		}
		break;

	case OS210_TYPE_DEFINE:
	case OS210_TYPE_DEFSTR:
		elem_define=(TEMPLATE_ELEM *)(elem_template->elem_var);
		define_value=*(int *)elem_define->elem_var;
		if(define_value<0)
			return -EINVAL;
		if(define_value>32768)
			return -EINVAL;
		retval=elem_attr->size*define_value;
		
		buf=kmalloc(retval,GFP_KERNEL);
		if(buf==NULL)
			return -ENOMEM;
		memcpy(buf,elem_data,retval);
		*(char **)addr=buf;
		break;
	case OS210_TYPE_DEFSTRARRAY:
		elem_define=(TEMPLATE_ELEM *)(elem_template->elem_var);
		define_value=*(int *)elem_define->elem_var;
		if(define_value<0)
			return -EINVAL;
		if(define_value>32768)
			return -EINVAL;
		retval=elem_attr->size*define_value;
		
		buf=kmalloc(retval,GFP_KERNEL);
		if(buf==NULL)
			return -ENOMEM;
		memcpy(buf,elem_data,elem_attr->size*define_value);
		*(char **)addr=buf;
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


int blob_2_struct(void * blob,void * addr,void * template)
{
	struct struct_template * struct_template;
	struct struct_template * curr_struct;
	void * stack;
	int bloboffset=0;
	int addroffset=0;
	int i;
	int value;
	int * define_value;
	int retval;

	TEMPLATE_ELEM * struct_elem;
	// use a pointer stack to finish the throughout of the template
	stack=init_pointer_stack(MAX_NAME_DEPTH);
	
	if(IS_ERR(stack))
		return stack;

	struct_template=(struct struct_template *)template;
	curr_struct = struct_template;
	
	i=0;
	// get the first elem
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

		// if this elem's elem_var is not empty, then it is a defining elem,we should get its value for later use
		switch(struct_elem->elem_desc->type)
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
				if(struct_elem->elem_var != 0)
				{	
					define_value = (int *)(struct_elem->elem_var);
					*define_value = blob_get_int_value(blob+bloboffset,struct_elem); 
				}
			default:
				break;
		}
		//  write struct value to blob
		retval = blob_2_struct_write_elem(blob+bloboffset,addr+addroffset,struct_elem);
		if(retval<0)
		{
			free_pointer_stack(stack);
			return retval;
		}
		bloboffset+=retval;
		addroffset+=struct_get_elem_size(struct_elem);
		struct_elem++;
	}	
	free_pointer_stack(stack);
	return bloboffset;
}

void * struct_get_elem_addr(void * elem,void * template)
{
	struct struct_template * struct_template;
	struct struct_template * curr_struct;
	void * stack;
	int addroffset=0;
	int i;
	int value;
	int * define_value;
	int retval;

	TEMPLATE_ELEM * struct_elem;
	// use a pointer stack to finish the throughout of the template
	stack=init_pointer_stack(MAX_NAME_DEPTH);
	
	if(IS_ERR(stack))
		return stack;

	struct_template=(struct struct_template *)template;
	curr_struct = struct_template;
	
	i=0;
	// get the first elem
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
				return -EINVAL;
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

		// if this elem is the target, then we break
		if(struct_elem==elem)
			break;

		// else, we sum the addr's offset
		addroffset+=struct_get_elem_size(struct_elem);
		struct_elem++;
	}
	free_pointer_stack(stack);
	return addroffset;
}

#ifdef USER_MODE

int struct_comp_elem(char * name,void * addr, void * elem_data,void * template)
{
	TEMPLATE_ELEM * elem;
	int addr_offset;
	elem=(TEMPLATE_ELEM *)read_elem_addr(name,template);
	if((elem == NULL)||IS_ERR(elem))
		return -EINVAL;

	addr_offset=struct_get_elem_addr(elem,template);
	if(addr_offset<0)
		return addr_offset;
	return struct_2_struct_comp_elem(addr+addr_offset,elem_data+addr_offset,elem);
}

int struct_read_elem(char * name,void * addr, void * elem_data,void * template)
{
	TEMPLATE_ELEM * elem;
	int addr_offset;
	elem=(TEMPLATE_ELEM *)read_elem_addr(name,template);
	if((elem == NULL)||IS_ERR(elem))
		return -EINVAL;

	addr_offset=struct_get_elem_addr(elem,template);
	if(addr_offset<0)
		return addr_offset;
	return struct_2_blob_write_elem(addr+addr_offset,elem_data,elem);
}

int struct_write_elem(char * name,void * addr, void * elem_data,void * template)
{
	TEMPLATE_ELEM * elem;
	int addr_offset;
	elem=(TEMPLATE_ELEM *)read_elem_addr(name,template);
	if((elem == NULL)||IS_ERR(elem))
		return -EINVAL;
	addr_offset=struct_get_elem_addr(elem,template);
	if(addr_offset<0)
		return addr_offset;
	return blob_2_struct_write_elem(elem_data,addr+addr_offset,elem);
}


int blob_2_text_write_elem(void * blob,char * string,TEMPLATE_ELEM * elem_template, int * stroffset)
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


	TEMPLATE_ELEM * elem_define;
	int define_value;


	elem_attr=elem_template->elem_desc;

	switch(elem_attr->type) {
		case OS210_TYPE_STRING :
	  	retval=elem_attr->size;
		int_value=strlen(blob);
		if(int_value >=retval)
		{
			memcpy(string+*stroffset,blob,retval);
			*stroffset+=retval;
		}
		else
		{
			memcpy(string+*stroffset,blob,int_value);
			*stroffset+=int_value;
		}
		break;
	case OS210_TYPE_INT :
	case TPM_TYPE_UINT32 :
		int_value=*(int *)blob;
		snprintf(string+*stroffset,bufsize,"%d",int_value);
		*stroffset+=strlen(string+*stroffset);
  		retval=sizeof(int);
		break;
	case OS210_TYPE_ENUM :
		{
  			retval=sizeof(int);
			int_value=*(int *)blob;
			if(int_value==0)
			{
				len=strlen(nulstring);
				snprintf(string+*stroffset,len,"%s",nulstring);
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
						snprintf(string+*stroffset,len,"%s",EnumList[i].name);
						*stroffset+=len;
						break;
					}
				}
				if(EnumList[i].name==NULL)
					return -EINVAL;
			}
		}
		break;
	case OS210_TYPE_FLAG :
		{
  			retval=sizeof(int);
			int_value=*(int *)blob;
			if(int_value==0)
			{
				len=strlen(nulstring);
				snprintf(string+*stroffset,len,"%s",nulstring);
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
			
				for(i=0;FlagList[i].name!=NULL;i++)
				{
					j=0;   // count the match flag num
					if(FlagList[i].value & int_value)
					{
						if(j!=0)  // not the first flag
						{
							sprintf(string+*stroffset,"|");
							*stroffset++;
	
						}	
						j++;
						int length=strlen(FlagList[i].name);
						snprintf(string+*stroffset,length+1,"%s",FlagList[i].name);
						*stroffset+=length;
					}
				}
			}
		}
		break;
	case OS210_TYPE_TIME:
		{
			retval=sizeof(time_t);
			struct tm * tm_time;
			time_t * t_time;
			if(tm_time==NULL)
				return -ENOMEM;

			tm_time = localtime(blob);
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
		break;
	case OS210_TYPE_UCHAR :
		retval=sizeof(unsigned char);
		sprintf(string+*stroffset,"%d",*(unsigned char *)blob);
		*stroffset+=strlen(string+*stroffset);
		break;
	case OS210_TYPE_USHORT :
	case TPM_TYPE_UINT16 :
		retval=sizeof(unsigned short);
		sprintf(string+*stroffset,"%d",*(unsigned short *)blob);
		*stroffset+=strlen(string+*stroffset);
		break;
	case OS210_TYPE_LONGLONG:
	case TPM_TYPE_UINT64 :
		retval=sizeof(unsigned long long);
		sprintf(string+*stroffset,"%d",*(unsigned long long *)blob);
		*stroffset+=strlen(string+*stroffset);
		break;
	case OS210_TYPE_BINDATA:
		retval=elem_attr->size;
		memset(buf,0,bufsize);
		bin_to_radix64(buf,elem_attr->size,blob);	
		sprintf(string+*stroffset,"%s",buf);
		*stroffset+=strlen(string+*stroffset);
		break;
	case OS210_TYPE_BITMAP:
		retval=elem_attr->size;
		tempbuf=(BYTE * )blob;
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
		break;
	case OS210_TYPE_HEXDATA:
		retval=elem_attr->size;
		tempbuf=(BYTE * )blob;
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
		break;
	case OS210_TYPE_BINARRAY:
		retval=elem_attr->size*(int)(elem_attr->attr);
		memset(buf,0,bufsize);
		for(i=0;i<elem_attr->size;i++)
		{
			bin_to_radix64(buf,(int)(elem_attr->attr),blob+i*(int)(elem_attr->attr));	
			sprintf(string+*stroffset,"%s ",buf);
			string+=strlen(string+*stroffset);
		}
		break;
	case OS210_TYPE_VSTRING:
		vstring.length=*(UINT16 *)blob;
		if((vstring.length <0) || (vstring.length>OS210_MAX_BUF))
		{
			return retval;	
		}
		retval=sizeof(UINT16)+vstring.length;
		vstring.String= (BYTE *)blob+sizeof(UINT16);
		memcpy(string+*stroffset,vstring.String,vstring.length);
		*stroffset+=vstring.length;
		break;
	case OS210_TYPE_ESTRING:
	case OS210_TYPE_JSONSTRING:
		{
			int length;
			length=strlen(blob);
			if(length <0)
			{
				retval=-EINVAL;	
			}
			if((elem_attr!=0) &&(length>elem_attr->size))
			{
				retval=-EINVAL;	
			}
			sprintf(string+*stroffset,"%s",blob);
			*stroffset+=length;
			retval=length+1;
		}
		break;

	case OS210_TYPE_ORGCHAIN:
	 	retval= 0;		
		break;
	case OS210_TYPE_DEFINE:
		elem_define=(TEMPLATE_ELEM *)(elem_template->elem_var);
		retval=elem_attr->size*(*(int*)(elem_define->elem_var));
		int_value=bin_to_radix64(buf,retval,blob);	
		if(int_value!=bin_to_radix64_len(retval))
				return -EINVAL;
		sprintf(string+*stroffset,"%s",buf);
		*stroffset+=int_value;
		break;
	case OS210_TYPE_DEFSTR:
		elem_define=(TEMPLATE_ELEM *)(elem_template->elem_var);
		retval=elem_attr->size*(*(int*)(elem_define->elem_var));
		memcpy(string+*stroffset,blob,retval);
		*stroffset+=retval;
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
		for(i=0;i<define_value;i++)
		{
			sprintf(string+*stroffset,"%s",blob+i*elem_attr->size);
			int_value=strlen(string+*stroffset);
			string[*stroffset+int_value]=' ';
			*stroffset+=int_value+1;
		}	
		break;
		
	case OS210_TYPE_NODATA:
	default:
		break;
	}	
 	return retval;
}

int struct_write_elem_text(char * name,void * addr, char * string,void * template)
{
	TEMPLATE_ELEM * elem;
	int addr_offset;
	char buffer[4096];
	int ret;
	int str_offset=0;
	elem=(TEMPLATE_ELEM *)read_elem_addr(name,template);
	if((elem == NULL)||IS_ERR(elem))
		return -EINVAL;
	addr_offset=struct_get_elem_addr(elem,template);
	if(addr_offset<0)
		return addr_offset;

	ret=struct_2_blob_write_elem(addr+addr_offset,buffer,elem);
	if(ret<0)
		return ret;
	ret=blob_2_text_write_elem(buffer,string,elem,&str_offset);
	if(ret<0)
		return ret;
	return str_offset;
}

int blob_2_text(void * blob, char * string,void * template,int *stroffset)
{
	struct struct_template * struct_template;
	struct struct_template * curr_struct;
	void * stack;
	int bloboffset=0;
	int i;
	int value;
	int * define_value;
	int retval;

	TEMPLATE_ELEM * struct_elem;
	// use a pointer stack to finish the throughout of the template
	stack=init_pointer_stack(MAX_NAME_DEPTH);
	
	if(IS_ERR(stack))
		return stack;

	struct_template=(struct struct_template *)template;
	curr_struct = struct_template;
	
	i=0;
	// get the first elem
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
				if(struct_elem->elem_var != 0)
				{	
					define_value = (int *)(struct_elem->elem_var);
					*define_value = blob_get_int_value(blob+bloboffset,struct_elem); 
				}
			default:
				break;
		}
		//  write struct value to blob
		retval = blob_2_text_write_elem(blob+bloboffset,string,struct_elem,stroffset);
		if(retval<0)
		{
			free_pointer_stack(stack);
			return retval;
		}
		bloboffset+=retval;
		*(string+*stroffset)='\t';
		(*stroffset)++;
		struct_elem++;
	}
	free_pointer_stack(stack);
	return bloboffset;
}

int text_2_blob_write_elem(char * string,void * blob,TEMPLATE_ELEM * elem_template)
{
	struct struct_elem_attr * elem_attr;
	const int bufsize=1024;
   	BYTE buf[bufsize];
	int retval;
	int int_value;
	unsigned char char_value;
	unsigned short short_value;
	long long long_long_value;
	int i,j;
	BYTE * data;
	V_String vstring;

	TEMPLATE_ELEM * elem_define;
	int define_value;

	elem_attr=elem_template->elem_desc;

	switch(elem_attr->type) {
		case OS210_TYPE_STRING :
	  	retval=elem_attr->size;
		int_value=strlen(string);
		if(int_value>=retval)
			memcpy(blob,string,retval);
		else
		{
			memset(blob,0,retval);
			memcpy(blob,string,int_value);
		}
		break;
	case OS210_TYPE_INT :
	case TPM_TYPE_UINT32 :
  		retval=sizeof(int);
		int_value=atoi(string);
		memcpy(blob,&int_value,retval);
		break;
	case OS210_TYPE_ENUM :
		{
  			retval=sizeof(int);
			if(!strcmp(nulstring,string))
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
			
				for(i=0;EnumList[i].name!=NULL;i++)
				{
					if(!strcmp(EnumList[i].name,string))
					{	
						int_value=EnumList[i].value;
						memcpy(blob,&int_value,retval);
						break;
					}
				}
				if(EnumList[i].name==NULL)
					return -EINVAL;
			}
		}
		break;
	case OS210_TYPE_FLAG :
		{
  			retval=sizeof(int);
			if(!strcmp(nulstring,string))
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
	
				for(i=0;i<strlen(string);i++)
				{
					if(string[i]=='|')
						continue;
					// duplicate one flag bit string
					temp_string[stroffset++]=string[i];
					if((string[i+1]!='|') && (string[i+1]!=0))
						continue;
					 
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

				memcpy(blob,&int_value,retval);
			}
		}
		break;
	case OS210_TYPE_TIME:
		{
			retval=sizeof(time_t);
			struct tm * tm_time;
			time_t * t_time;
			tm_time=kmalloc(sizeof(struct tm),GFP_KERNEL);
			if(tm_time==NULL)
				return -ENOMEM;
			// the string should be like 20111117110000
			if(strlen(string)!=14)
				return -EINVAL;
			char buf[5];
			//convert year
			memcpy(buf,string,4);
			buf[4]=0;
			tm_time->tm_year=atoi(buf)-1900;
			//convert month
			memcpy(buf,string+4,2);
			buf[2]=0;
			tm_time->tm_year=atoi(buf)-1;
			//convert day
			memcpy(buf,string+6,2);
			buf[2]=0;
			tm_time->tm_year=atoi(buf)-1;
			//convert hour
			memcpy(buf,string+8,2);
			buf[2]=0;
			tm_time->tm_year=atoi(buf)-1;
			//convert minute
			memcpy(buf,string+10,2);
			buf[2]=0;
			tm_time->tm_year=atoi(buf)-1;
			//convert second
			memcpy(buf,string+12,2);
			buf[2]=0;
			tm_time->tm_year=atoi(buf)-1;
			t_time=mktime(tm_time);
			memcpy(blob,tm_time,sizeof(time_t));
			free(tm_time);
		}
		break;
	case OS210_TYPE_UCHAR :
  		retval=sizeof(unsigned char);
		char_value=(char)atoi(string);
		memcpy(blob,&char_value,retval);
		break;
	case OS210_TYPE_USHORT :
	case TPM_TYPE_UINT16 :
  		retval=sizeof(unsigned short);
		short_value=(unsigned short)atoi(string);
		memcpy(blob,&short_value,retval);
		break;
	case OS210_TYPE_LONGLONG:
	case TPM_TYPE_UINT64 :
  		retval=sizeof(long long);
		long_long_value=(long long)atoi(string);
		memcpy(blob,&long_long_value,retval);
		break;
	case OS210_TYPE_BINDATA:
		retval=elem_attr->size;
		radix64_to_bin(blob,bin_to_radix64_len(retval),string);
		break;
	case OS210_TYPE_BITMAP:
		{
			char * tempstring;
			BYTE * tempbuf;
			retval=elem_attr->size;
			tempbuf=(BYTE * )blob;
			tempstring=string;
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
		{
			char * tempstring;
			BYTE * tempbuf;
			retval=elem_attr->size;
			tempbuf=(BYTE * )blob;
			tempstring=string;
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
			break;
		}
	case OS210_TYPE_BINARRAY:
		{
			char * tempstring;
			int string_len;
			int bin_len;
			retval=elem_attr->size*(int)(elem_attr->attr);
			tempstring=string;
			string_len=bin_to_radix64_len((int)(elem_attr->attr));
			for(i=0;i<elem_attr->size;i++)
			{
				while(*tempstring==' ')
					tempstring++;
				bin_len=radix64_to_bin(blob+i*(int)(elem_attr->attr),string_len,tempstring);
				if(bin_len!=(int)(elem_attr->attr))
					return -EINVAL;
				tempstring+=string_len;
			}
		}
		break;
	case OS210_TYPE_VSTRING:
		vstring.length=strlen(string);
		if((vstring.length <0) || vstring.length> OS210_MAX_BUF)
		{
			retval=-EINVAL;	
		}
		retval=sizeof(UINT16)+vstring.length;
		short_value=vstring.length;
		memcpy(blob,&short_value,sizeof(UINT16));
		memcpy(blob+sizeof(UINT16),string,vstring.length);
		break;
	case OS210_TYPE_ESTRING:
	case OS210_TYPE_JSONSTRING:
		{
			int length;
			length=strlen(string);
			if(length <0)
			{
				retval=-EINVAL;	
			}
			if((elem_attr->size!=0) && (length>elem_attr->size))
			{
				retval=-EINVAL;	
			}
			retval=length+1;
			memcpy(blob,string,retval);
		}
		break;


	case OS210_TYPE_ORGCHAIN:
	 	retval= 0;		
		break;
	case OS210_TYPE_DEFINE:
		elem_define=(TEMPLATE_ELEM *)(elem_template->elem_var);
		retval=elem_attr->size*(*(int*)(elem_define->elem_var));
		if(retval!=radix64_to_bin(blob,strlen(string),string))
			return -EINVAL;
		break;
	case OS210_TYPE_DEFSTR:
		elem_define=(TEMPLATE_ELEM *)(elem_template->elem_var);
		retval=elem_attr->size*(*(int*)(elem_define->elem_var));
		memcpy(blob,string,retval);
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
		memset(blob,0,retval);
		for(i=0;i<define_value;i++)
		{
			while(string[int_value]==' ')
				int_value++;
			for(j=0;j<elem_attr->size;j++)
			{
				if(string[int_value]==' ')
				{
					int_value++;
					break;
				}
				*(char *)(blob+i*elem_attr->size+j)=string[int_value++];
			}
		}
		break;
		
	case OS210_TYPE_NODATA:
	default:
		break;
	}	
 	return retval;
}

int struct_read_elem_text(char * name,void * addr, char * text,void * template)
{
	TEMPLATE_ELEM * elem;
	int addr_offset;
	char buffer[4096];
	int ret;
	elem=(TEMPLATE_ELEM *)read_elem_addr(name,template);
	if((elem == NULL)||IS_ERR(elem))
		return -EINVAL;
	addr_offset=struct_get_elem_addr(elem,template);
	if(addr_offset<0)
		return addr_offset;
	ret=text_2_blob_write_elem(text,buffer,elem);
	if(ret<0)
		return ret;
	return blob_2_struct_write_elem(buffer,addr+addr_offset,elem);
}

int struct_comp_elem_text(char * name,void * addr, char * text,void * template)
{
	TEMPLATE_ELEM * elem;
	int addr_offset;
	char buffer1[256];
	char buffer2[256];
	int ret;
	elem=(TEMPLATE_ELEM *)read_elem_addr(name,template);
	if((elem == NULL)||IS_ERR(elem))
		return -EINVAL;
	addr_offset=struct_get_elem_addr(elem,template);
	if(addr_offset<0)
		return addr_offset;
	ret=text_2_blob_write_elem(text,buffer1,elem);
	if(ret<0)
		return ret;
	ret=blob_2_struct_write_elem(buffer1,buffer2,elem);
	if(ret<0)
		return ret;
//	ret=struct_read_elem(name,addr+addr_offset,buffer1,elem);
//	if(ret<0)
//		return ret;
	return struct_2_struct_comp_elem(buffer2,addr+addr_offset,elem);
}

int text_2_blob(char * string,void * blob, void * template, int * stroffset)
{
	struct struct_template * struct_template;
	struct struct_template * curr_struct;
	void * stack;
	int bloboffset=0;
	int retval;
	int i,j;
	int value;
	int * define_value;

        int start,offset;
   	int tempstroffset;
	const int bufsize=1024;
	char buf[bufsize];

	TEMPLATE_ELEM * struct_elem;
	// use a pointer stack to finish the throughout of the template
	stack=init_pointer_stack(MAX_NAME_DEPTH);
	
	if(IS_ERR(stack))
		return stack;

	struct_template=(struct struct_template *)template;
	curr_struct = struct_template;
	
	i=0;
	// get the first elem
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

		// get the valid string
		retval=0;

 		while(!IsAValidChar(string[(*stroffset)]))
		{
			(*stroffset)++;
		}
		start=*stroffset;

  		while(IsAValidChar(string[(*stroffset)]))
			(*stroffset)++;

 		tempstroffset=*stroffset-start;
		if(tempstroffset>=bufsize)
		{
			free_pointer_stack(stack);
			return -EINVAL;
		}
   		memcpy(buf,string+start,tempstroffset);
   		buf[tempstroffset]=0;

		//  write text value to blob
		if((retval=text_2_blob_write_elem(buf,blob+bloboffset,struct_elem))<0)
		{
			return retval;
		}

		// if this elem's elem_var is not empty, then it is a defining elem,we should get its value for later use
		switch(struct_elem->elem_desc->type)
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
				if(struct_elem->elem_var != 0)
				{	
					define_value = (int *)(struct_elem->elem_var);
					*define_value = blob_get_int_value(blob+bloboffset,struct_elem); 
				}
			default:
				break;
		}
		bloboffset+=retval;
		struct_elem++;
	}
	free_pointer_stack(stack);
	return bloboffset;
}

#endif
void * clone_struct(void * addr, void * struct_template)
{
	void * new_struct;
	BYTE *buffer;
	int blob_size;
	int retval;
	retval=alloc_struct(&new_struct,struct_template);
	if(retval<0)
		return NULL;

	buffer=kmalloc(32768,GFP_KERNEL);
	if(buffer==NULL)
	{
		free_struct(new_struct,struct_template);
		return NULL;
	}
	blob_size=struct_2_blob(addr,buffer,struct_template);
	if(blob_size<=0)
	{
		free_struct(new_struct,struct_template);
		free(buffer);
		return NULL;
	}
	retval=blob_2_struct(buffer,new_struct,struct_template);
	free(buffer);

	if(retval!=blob_size)
	{
		free_struct(new_struct,struct_template);
		return NULL;
	}
	return new_struct;

}

void * struct_get_elem_byname(char * elem,void * template)
{
	struct struct_template * struct_template;
	struct struct_template * curr_struct;
	void * stack;
	int addroffset=0;
	int i;
	int value;
	int * define_value;
	int retval;

	TEMPLATE_ELEM * struct_elem;
	// use a pointer stack to finish the throughout of the template
	stack=init_pointer_stack(MAX_NAME_DEPTH);
	
	if(IS_ERR(stack))
		return stack;

	struct_template=(struct struct_template *)template;
	curr_struct = struct_template;
	
	i=0;
	// get the first elem
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
				return -EINVAL;
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

		// if this elem is the target, then we break
		if(struct_elem==elem)
			break;

		// else, we sum the addr's offset
		addroffset+=struct_get_elem_size(struct_elem);
		struct_elem++;
	}
	free_pointer_stack(stack);
	return addroffset;
}

void * struct_get_elem_attr(char * name,void * template)
{
	TEMPLATE_ELEM * elem;
	elem=(TEMPLATE_ELEM *)read_elem_addr(name,template);
	if((elem == NULL)||IS_ERR(elem))
		return -EINVAL;

	return elem->elem_desc->attr;
}

int struct_set_elem_var(char * name,void * var,void * template)
{
	TEMPLATE_ELEM * elem;
	elem=(TEMPLATE_ELEM *)read_elem_addr(name,template);
	if((elem == NULL)||IS_ERR(elem))
		return -EINVAL;
	elem->elem_var=var;

	return 0;
}
void * Memcpy(void * dest,void * src, unsigned int count)
{
	if(dest == src)
		return src;
	char * d=(char *)dest;
	char * s=(char *)src;
	while(count-->0)
		*d++=*s++;
	return dest;
}
