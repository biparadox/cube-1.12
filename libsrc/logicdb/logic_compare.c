/*************************************************
*       高安全级别Linux系统项目
*
*	程序名称: 	比较函数执行代码
*	文件名:		label_compare.c

*	日期:    	2008-05-18
*	作者:    	胡俊
*	模块描述:  	四级Linux系统标记管理模块各安全策略项的比较函数执行代码
* 修改记录:       
* 修改描述:       
*************************************************/
#ifndef USER_MODE

#include <linux/ctype.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/netlink.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/list.h>

#else

#include <stdlib.h> 
#include <string.h> 
#include <errno.h> 
#include  "../include/kernel_comp.h"
#include "../include/list.h"

#endif


#include "../include/data_type.h"
#include "../include/extern_struct.h" 
#include "../include/extern_interface.h" 
#include "../include/extern_defno.h"   
#include "logic_compare.h"     
#include "../include/attrlist.h"         
#include "../include/struct_deal.h"       


char * label_get_tailname(char * name)
{
	char* temp;
	int offset;
	
	offset = strlen(name);
	if(offset==0)
		return NULL;
	temp=name+offset;
	while(temp!= name)
	{
		if(*(temp-1) =='/')
			break;
		temp--;
	}
	return temp;
}
int os210_comp_path(char * path1, char * path2);
int os210_comp_group(char * grouplist,char * groupname);

static __inline__ int os210_comp_vstring(V_String * string1,V_String * string2)
{
	int retval;
	if(string1->length > string2->length)
	{
		retval= strncmp((char *)string1->String,(char *)string2->String,
			string2->length);
		if(retval==0)  // if head of two string is equal,then the 
			       // longer string is small
			return -1;
		return retval;
	}
	retval= strncmp((char *)string1->String,(char *)string2->String,
		string1->length);
	if(retval==0)
	{
		if(string2->length > string1->length)
			return 1;
	}
	return retval;
}

/* 
int label_user_comp_euserid(struct list_head * head, int uid)
{
	User_Info  * userinfo;
 	Record_List * record;

	// 首先对比尾部名称	
	record = list_entry(head,Record_List,list);

	userinfo = (User_Info *) record->record;
	if(userinfo==NULL)
        	return -EINVAL;

	char radix[40];
	bin_to_radix64(radix,16,userinfo->KeyID+1);
	printk("key id is %s\n!",radix);
	bin_to_radix64(radix,16,ekeyid);
	printk("ekey id is %s\n!",radix);

	return !(userinfo->UserID==uid);
}*/

int label_userid_comp_userid(struct list_head * head, int uid)
{
	USERID_POLICY  * useridrecord;
 	Record_List * record;

	// 首先对比尾部名称	
	record = list_entry(head,Record_List,list);

	useridrecord = (USERID_POLICY *) record->record;
	if(useridrecord==NULL)
        	return -EINVAL;
	return !(useridrecord->userid==uid);
}
 
int label_authuser_typecomp(int findtype,struct list_head * head, char * name) 
{                                                             
	USERID_POLICY  * useridrecord;
 	Record_List * record;

	// 首先对比尾部名称	
	record = list_entry(head,Record_List,list);

	useridrecord = (USERID_POLICY *) record->record;
	if(useridrecord==NULL)
        	return -EINVAL;
	if(useridrecord->SubName.String == NULL)
		return -EINVAL;
	int namelen=strlen(name);
//	if(namelen!=useridrecord->SubName.length)
//		return namelen-useridrecord->SubName.length;
	return strcmp(useridrecord->SubName.String,name);        
}

int label_obj_comp_markpolicy(struct list_head * head, char * policyname)
{
	OBJ_LABEL * objlabel;
 	Record_List * record;

	// 首先对比尾部名称	
	record = list_entry(head,Record_List,list);

	objlabel = (OBJ_LABEL *) record->record;
	if(objlabel==NULL)
        	return -EINVAL;
	if(objlabel->ObjName.String == NULL)
		return -EINVAL;
		
	return strcmp((char *)objlabel->ObjName.String,policyname);
}

int label_obj_comp_name(struct list_head * head, char * name)
{
	OBJ_LABEL * objlabel;
 	Record_List * record;

	// 首先对比尾部名称	
	record = list_entry(head,Record_List,list);

	objlabel = (OBJ_LABEL *) record->record;
	if(objlabel==NULL)
        	return -EINVAL;
	if(objlabel->ObjName.String == NULL)
		return -EINVAL;
		
	return os210_comp_namepath((char *)objlabel->ObjName.String,name);
}
/*
int label_obj_typecomp_name(int findtype,struct list_head * head, char * name)
{
	int retval;
	OBJ_LABEL * objlabel;
 	Record_List * record;

	// 首先对比尾部名称	
	record = list_entry(head,Record_List,list);
	objlabel = (OBJ_LABEL *) record->record;
	if(objlabel==NULL)
        	return -EINVAL;
	if(objlabel->ObjName.String == NULL)
		return -EINVAL;

	switch(findtype)
	{
		case FINDTYPE_FILENAME_UNINAME:
			if(objlabel->ObjName.String[0] != '*')
		             	return (int)'*'; 
			retval=strcmp((char *)(objlabel->ObjName.String+2),
				name);
		case FINDTYPE_FILENAME_MINUPPER:
			if(objlabel->ObjName.String[
				objlabel->ObjName.length-1] != '*')
				return -EINVAL;
			retval=os210_comp_path((char *)objlabel->ObjName.String,
				name);
		default:
			return -EINVAL;
	}
	return retval;
}
*/
int label_obj_match_name(struct list_head * head, char * name)
{
	OBJ_LABEL * objlabel;
 	Record_List * record;

	// 首先对比尾部名称	
	record = list_entry(head,Record_List,list);

	objlabel = (OBJ_LABEL *) record->record;
	if(objlabel==NULL)
        	return -EINVAL;
	if(objlabel->ObjName.String == NULL)
		return -EINVAL;

	if(objlabel->ObjName.String[objlabel->ObjName.length-1] != '*')
		return -EINVAL;
	return os210_comp_path((char *)objlabel->ObjName.String,name);
}


int label_obj_comp_uniname(struct list_head * head, char * name)
{
	OBJ_LABEL * objlabel;
 	Record_List * record;

	// 首先对比尾部名称	
	record = list_entry(head,Record_List,list);
	objlabel = (OBJ_LABEL *) record->record;
	if(objlabel==NULL)
        	return -EINVAL;
	if(objlabel->ObjName.String == NULL)
		return -EINVAL;
	if(objlabel->ObjName.String[0] != '*')
		return (int)'*'; 
	return strcmp((char *)(objlabel->ObjName.String+2),name);
}

int label_proc_comp_name(struct list_head * head, char * name)
{
	SUB_LABEL * proclabel;
 	Record_List * record;

	// 首先对比尾部名称	
	record = list_entry(head,Record_List,list);

	proclabel = (SUB_LABEL *) record->record;
	if(proclabel==NULL)
        	return -EINVAL;
	if(proclabel->SubType != SUB_TYPE_PROC)//7.18
		return -EINVAL;//7.18
	if(proclabel->SubName.String == NULL)
		return -EINVAL;
	if(proclabel->SubName.String[0] != '*')
		return (int)'*'; 
	return strcmp((char *)(proclabel->SubName.String+2),name);
}

int label_proc_comp_uniname(struct list_head * head, char * name)
{
	SUB_LABEL * proclabel;
 	Record_List * record;

	// 首先对比尾部名称	
	record = list_entry(head,Record_List,list);

	proclabel = (SUB_LABEL *) record->record;
	if(proclabel==NULL)
        	return -EINVAL;
	if(proclabel->SubType != SUB_TYPE_PROC)
		return -EINVAL;
	if(proclabel->SubName.String == NULL)
		return -EINVAL;
	return os210_comp_path((char *)proclabel->SubName.String,name);
}

int label_obj_comp_elem(struct list_head * head, struct list_head * elem)
{
	OBJ_LABEL * objlabel, *elemobjlabel;
 	Record_List * record;
 	Record_List * elemrecord;

	record = list_entry(head,Record_List,list);
	elemrecord = list_entry(elem,Record_List,list);

	objlabel = (OBJ_LABEL *) record->record;
	elemobjlabel = (OBJ_LABEL *) elemrecord->record;
	if(objlabel==NULL)
        	return -EINVAL;
	if(elemobjlabel==NULL)
        	return -EINVAL;
	if(objlabel->ObjName.String == NULL)
		return -EINVAL;
	return os210_comp_path((char *)objlabel->ObjName.String,
		(char *)elemobjlabel->ObjName.String);
}

int label_obj_match_elem(struct list_head * head, struct list_head * elem)
{
	OBJ_LABEL * objlabel, *elemobjlabel;
 	Record_List * record;
 	Record_List * elemrecord;

	record = list_entry(head,Record_List,list);
	elemrecord = list_entry(elem,Record_List,list);

	objlabel = (OBJ_LABEL *) record->record;
	elemobjlabel = (OBJ_LABEL *) elemrecord->record;
	if(objlabel==NULL)
        	return -EINVAL;
	if(elemobjlabel==NULL)
        	return -EINVAL;
	if(objlabel->ObjName.String == NULL)
		return -EINVAL;
//	printk("label compare elem! name %s len %d!\n",
//		objlabel->ObjName.String,objlabel->ObjName.length);	
	if(objlabel->ObjName.String[objlabel->ObjName.length-1] != '*')
		return -EINVAL;
	return os210_comp_path((char *)objlabel->ObjName.String,
		(char *)elemobjlabel->ObjName.String);
}

int label_sub_comp_name(struct list_head * head, void * name) 
{                                                             
	SUB_LABEL * sublabel;                                    
	Record_List * record;                             
	char * string;
	string=(char *)name;
	record = list_entry(head,Record_List,list);              
	sublabel = (SUB_LABEL *) record->record;                      
	if(sublabel == NULL)                                            
           return -EINVAL;                       
	if(sublabel->SubName.String == NULL)
		return -ENODEV;
/*
	printk ("subname is %s, len is %d! \n",sublabel->SubName.String,
			sublabel->SubName.length);
	printk	("compare name is %s! \n",(char *)name);
*/
	int namelen=strlen(string);
	if(sublabel->SubName.length == namelen)
		return strncmp((char *)sublabel->SubName.String,string,
			sublabel->SubName.length);        
	return 1;
}

/* 
int label_user_comp_name(struct list_head * head, char * name) 
{                                                             
	User_Info * userinfo;                                    
	Record_List * record;                             
	record = list_entry(head,Record_List,list);              
	userinfo = (User_Info *) record->record;                      
	if(userinfo == NULL)                                            
           return -EINVAL;                       
	if(userinfo->UserName == NULL)
		return -ERR_LABEL_NOSUB;

	printk("user name in list is %s\n!",userinfo->UserName);
	printk("comp name is %s\n!",name);

	return strcmp((char *)userinfo->UserName,name);        
}*/

int label_sub_comp_label(struct list_head * head, void * label) 
{
	SUB_LABEL * sublabel;
	sublabel = (SUB_LABEL *)label;
	return label_sub_comp_name(head,sublabel->SubName.String);
}
int label_obj_comp_label(struct list_head * head, void * label) 
{
	OBJ_LABEL * objlabel;
	objlabel = (OBJ_LABEL *)label;
	return label_obj_comp_name(head,objlabel->ObjName.String);
}
/*
int label_user_comp_label(struct list_head * head, void * label) 
{
	User_Info * userlabel;
	userlabel = (User_Info *)label;
	return label_user_comp_name(head,userlabel->UserName);
}*/

int label_sub_comp_group(struct list_head * head, char * groupname) 
{                                                             
	SUB_LABEL * sublabel;                                    
	Record_List * record;                             
                                                              
	record = list_entry(head,Record_List,list);              
                                                              
	sublabel = (SUB_LABEL *) record->record;                      
	if(sublabel==NULL)                                            
        	return -EINVAL;                       
	if(sublabel->GroupName.String == NULL)
		return -ENODEV;
	return strncmp((char *)(sublabel->GroupName.String),
		groupname,sublabel->GroupName.length);        
} 

int label_dac_comp_record(struct list_head * head, DAC_POLICY * dacrecord) 
{                                                             
	DAC_POLICY * dacpolicy;
//	   DAC_POLICYFile * dacrecord;
     	Record_List * record;
 	int retval;
	retval=0;                             
                                                              
//	   dacrecord = (DAC_POLICYFile *) record;                                    

     	record = list_entry(head,Record_List,list);              
                                                              
	dacpolicy = (DAC_POLICY *) record->record;                      
     	if(dacpolicy==NULL)                                            
        	return -EINVAL; 
	if(dacpolicy->SubName.length == dacrecord->SubName.length)
	{	
 		if( !strncmp((char *)dacpolicy->SubName.String,
   			(char *)dacrecord->SubName.String,
			dacpolicy->SubName.length))
     		{
			return strncmp((char *)dacpolicy->ObjName.String,
   				(char *)dacrecord->ObjName.String,
				dacpolicy->ObjName.length);
     		}
	}     
 	return  1;
} 

int label_dac_comp_match(struct list_head * head, void * dacrecord) 
{                                                             
	DAC_POLICY * dacpolicy;
//	   DAC_POLICYFile * dacrecord;
     	Record_List * record;
	struct dac_comp_struct
	{
		SUB_LABEL * sublabel;
		OBJ_LABEL * objlabel;
		BYTE 	mode;
	} * dac_comp;
 	int retval;
	char * group_list;
	char *groupname;
	char * objname,*pobjname;
	int i,pos;
	int state;  // record the comp state, 0 is not begin,
		    // 1 is mode match, 2 is name match, 3 is group match
		    // 4 is objname match


	dac_comp = (struct dac_comp_struct *)dacrecord;
	retval=0; 
	state=0;
                                                              
//	   dacrecord = (DAC_POLICYFile *) record;                                    
     	record = list_entry(head,Record_List,list);              
                                                              
	dacpolicy = (DAC_POLICY *) record->record;                      
     	if(dacpolicy==NULL){      
        	return -EINVAL; 
}
//	printk("1dac_comp_match function: subname  %s objname %s!\n",
//			dac_comp->sublabel->SubName.String,
//			dac_comp->objlabel->ObjName.String);
//	printk("1.5dac_comp_match function: mode  %x policy mode %x!\n",
//			dac_comp->mode,dacpolicy->OpType);
//	os210_dbg("dac_comp_match function: policy subname  %s objname %s!\n",
//			dacpolicy->SubName.String,
//			dacpolicy->ObjName.String);

	// first: compare the mode and the DAC optype
	if((dac_comp->mode & dacpolicy->OpType) != dac_comp->mode)
	{
		return -ENODEV; 
	}
	if(IS_ERR(dac_comp->objlabel->ObjName.String))
		return -EINVAL;

	state=1;
	// next: compare if the subname is matched
	if(!strcmp(dacpolicy->SubName.String,"*"))
	{
		state =2;
	}
	else if(dac_comp->sublabel->SubName.length ==
		dacpolicy->SubName.length)
	{
		if(!strncmp(dac_comp->sublabel->SubName.String,
			dacpolicy->SubName.String,
			dacpolicy->SubName.length))
			state=2;
	}
//       printk("2dac_comp_match: finish the sublabel compare!\n");
	// third: if name not match compare if the groupname is matched
	if(state == 1)
	{
		groupname = (char *)kmalloc(40,GFP_KERNEL);
		pos =0;
		group_list = dac_comp->sublabel->GroupName.String;
		if(group_list != NULL)
		{
			for(i=0;i<=dac_comp->sublabel->GroupName.length;i++)
			{
				groupname[pos++]=group_list[i];
				if((group_list[i]==';') ||(group_list[i]=='\0'))
				{
					groupname[pos]='\0';
					if(pos != dacpolicy->SubName.length)
						return -ENODEV;
					if(!strncmp(groupname,
						dacpolicy->SubName.String,
						pos))
					{
						state = 2;
						break;
					}
					pos=0;
				}
			}
		}
		kfree(groupname);
	}

//	printk("3dac_comp_match: finish the group compare!\n");
	if(state != 2)
		return -ENODEV;

	// last: compare if the objname is matched
	
	pobjname = dacpolicy->ObjName.String;
	if(pobjname[0]=='*')
	{
		objname = label_get_tailname(
			dac_comp->objlabel->ObjName.String);
	
		if(strlen(objname) == dacpolicy->ObjName.length-2)
		{
			if( strncmp(objname,(char *)(pobjname+2),
				dacpolicy->ObjName.length-1))
				return -ENODEV;
		}
		return 0;
	}

//	printk("4dac_comp_match: finish the uniname obj compare!\n");
	
	if(dac_comp->objlabel->ObjName.length >= dacpolicy->ObjName.length)
	{
		objname = dac_comp->objlabel->ObjName.String;
		retval = os210_comp_path(objname,pobjname);
//		printk("5dac_comp_match: comp path %s %s result %d!\n",
//			objname,pobjname,retval);
		if((retval == 0) || (retval == 2))
			// objname = pobjname or pobjname include objname 
			return 0;
	}

 	return  -ENODEV;
} 

int label_priv_comp_record(struct list_head * head, 
	PRIV_POLICY * privrecord) 
{                                                             
	PRIV_POLICY * privpolicy;
//	   DAC_POLICYFile * dacrecord;
	Record_List * record;
     	int retval;
	retval=0;                             

      	record = list_entry(head,Record_List,list);              
                                                              
	privpolicy = (PRIV_POLICY *) record->record;                      
	if(privpolicy==NULL)                                            
        	return -EINVAL; 

	if(!os210_comp_vstring(&(privpolicy->SubName),&(privrecord->SubName)))
	{
	 	if (!os210_comp_vstring(&(privpolicy->ObjName),
     			&(privrecord->ObjName)))
		{
 			return os210_comp_vstring(&(privpolicy->AuthOwnerName),
				&(privrecord->AuthOwnerName));
     		}
	}
     	return  -ENODEV;
} 

int label_priv_comp_match(struct list_head * head, void * privrecord) 
{                                                             
	PRIV_POLICY * privpolicy;
//	   DAC_POLICYFile * dacrecord;
     	Record_List * record;
	struct priv_comp_struct
	{
		SUB_LABEL * sublabel;
		OBJ_LABEL * objlabel;
		BYTE 	mode;
	} * priv_comp;
 	int retval;
	char * objname,*pobjname;
	int state;  // record the comp state, 0 is not begin,
		    // 1 is mode match, 2 is name match, 3 is group match
		    // 4 is objname match
	priv_comp = (struct priv_comp_struct *)privrecord;
	retval=0; 
	state=0;
                                                              
//	   dacrecord = (DAC_POLICYFile *) record;                                    
     	record = list_entry(head,Record_List,list);              
                                                              
	privpolicy = (PRIV_POLICY *) record->record;                      
     	if(privpolicy==NULL)                                            
        	return -EINVAL; 

	// first: compare the mode and the DAC optype
	if((priv_comp->mode & privpolicy->OpType) != priv_comp->mode)
	{
		return -ENODEV; 
	}
	if(IS_ERR(priv_comp->objlabel->ObjName.String))
		return -ENODEV;

	if(os210_comp_vstring(&(priv_comp->sublabel->SubName),
		&(privpolicy->SubName)))
		return -ENODEV;

	// last: compare if the objname is matched
	
	pobjname = privpolicy->ObjName.String;
	if(pobjname[0]=='*')
	{
		objname = label_get_tailname(
			priv_comp->objlabel->ObjName.String);
	
		if(strlen(objname) == privpolicy->ObjName.length-2)
		{
			if( strncmp(objname,(char *)(pobjname+2),
				privpolicy->ObjName.length-1))
				return -ENODEV;
		}
		return 0;
	}
	
	if(priv_comp->objlabel->ObjName.length >= privpolicy->ObjName.length)
	{
		objname = priv_comp->objlabel->ObjName.String;
		retval = os210_comp_path(objname,pobjname);
//		printk("5dac_comp_match: comp path %s %s result %d!\n",
//			objname,pobjname,retval);
		if((retval == 0) || (retval == 2))
			// objname = pobjname or pobjname include objname 
			return 0;
	}
 	return  -ENODEV;
} 
                                                              
int get_vaild_path_elem(char * path, char * elem)
{
        int i=0,j=0;
//	printk("get valid path elem! %s %s \n",path,elem);
        while((path[i] == ' ') || (path[i]== '/'))
               i++;
        while((path[i]!='/') && (path[i]!=0))
        {
                elem[j++]= path[i++];
        }
        elem[j]=0;
        return i;
}

/*************************************************
  *     名称:  文件路径比较函数
  *     描述:  比较两文件路径,
  *     输入:  path1: 文件路径1
  *            path2: 文件路径2
  *     输出:  无
  *       返回: 0: 两文件路径相同
  *             1: path1包含path2 (如path1: /src/ path2: /src/a.c)
  *             2: path2包含path1
  *             负值： 两路径互不包含
  *     其他:  无
*************************************************/
#define OS210_NAME_MAXLEN 1024

int os210_comp_path(char * path1, char * path2)
{
	char * buffer;
        char * temp1;
        char * temp2;
        int n1,n2;
	int retval;
        n1=0;
        n2=0;
	
	buffer = (char *)kmalloc(512,GFP_KERNEL);
	if(buffer == NULL)
		return -ENOMEM;
	temp1=buffer;
	temp2=buffer+256;
	memset(buffer,0,512);
        do
        {
                // 取路径元素
                n1 += get_vaild_path_elem(path1+n1,temp1);
                n2 += get_vaild_path_elem(path2+n2,temp2);

                // 若path1已结尾
                if((temp1[0]==0) || 
			((temp1[0] == '*') && (!temp1[1])))
                {
                        if((temp2[0] == 0) || 
				((temp2[0] == '*')&& (!temp2[1]))) // 若path2也结尾,则两路径相同
			{
				retval =0;
			}
			else
			{
                       		retval =1;        // path1包含path2
			}
			break;
                }
                if((temp2[0] == 0) ||
			((temp2[0] == '*')&& (!temp2[1]))) //若path2结尾
		{
			retval=2;
			break;
		}       // path2包含path1
                if(strcmp(temp1,temp2)!=0)
		{	
			retval = -1;
			break; //两路径不同
		}
        }while(1);
	kfree(buffer);
        return retval;
}

int os210_comp_namepath(char * path1, char * path2)
{
	char * buffer;
        char * temp1;
        char * temp2;
        int n1,n2;
	int retval;
        n1=0;
        n2=0;
	
	buffer = (char *)kmalloc(512,GFP_KERNEL);
	if(buffer == NULL)
		return -ENOMEM;
	temp1=buffer;
	temp2=buffer+256;
	memset(buffer,0,512);
        do
        {
                // 取路径元素
                n1 += get_vaild_path_elem(path1+n1,temp1);
                n2 += get_vaild_path_elem(path2+n2,temp2);

                // 若path1已结尾
                if(temp1[0]==0)
                {
                        if(temp2[0] == 0) // 若path2也结尾,则两路径相同
			{
				retval =0;
			}
			else
			{
                       		retval =1;        // path1包含path2
			}
			break;
                }
                if(temp2[0] == 0) //若path2结尾
		{
			retval=2;
			break;
		}       // path2包含path1
                if(strcmp(temp1,temp2)!=0)
		{	
			retval = -1;
			break; //两路径不同
		}
        }while(1);
	kfree(buffer);
        return retval;
}
/*************************************************
  *     名称:  组名称比较函数
  *     描述:  比较一个组名是否包含于组列表之中,
  *     输入:  grouplist: 组列表
  *            groupname: 组名称
  *     输出:  无
  *     返回:   0: 组名称在组列表之中
  *             正值: 组名称不在组列表之中
  *             负值：致命错误
  *     其他:  无
*************************************************/

int os210_comp_group(char * grouplist,char * groupname)
{
	char comparename[21];
	int i,offset;
	offset=0;
		
	while(grouplist[offset]!= 0)
	{
		   i=0;
		   while((grouplist[offset]!=';')||(grouplist[offset]!=0))
		   {
			     comparename[i++]=grouplist[offset++];
			     if(i >20)
			     		return -EINVAL;
			 }
			 comparename[i]=0;
			 if(strcmp(comparename,groupname) == 0)
			 			return 0;
			 if(grouplist[offset++] ==0)
					  break;			
	}
	return 1; 
}


char * label_get_dirname(char * name)
{
	char *temp;
	int offset;
	temp = kmalloc(1024,GFP_KERNEL);
	if(temp == NULL)
		return temp;
	
	temp[0]='/';
	strcpy(temp+1,name);	
	for(offset=strlen(temp);offset>0;offset--)
	{
		if(temp[offset]=='/')
		{
			temp[offset+1]=0;	
			break;
		}
	}
	return temp;
}
