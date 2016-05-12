#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "../include/kernel_comp.h"
#include "../include/list.h"

#include "../include/data_type.h"
#include "../include/struct_deal.h"
#include "../include/extern_struct.h"
#include "../include/extern_interface.h"
#include "../include/extern_struct_desc.h"
#include "../include/extern_defno.h"
#include "../include/attrlist.h"
//#include "../logic_compare.h"
#include "../include/logic_baselib.h"
//#include "../x509.h"
//#include "../pem2der.h"
#include "policy_ui.h"

#define MAX_NAME_LEN 1024 
#define MAX_LINE_LEN 1024 
#define OS210_MAX_BUF 1024
#define POLICY_MAX_BUF 4096

struct Policy_Filelist
{
	char *PolicyType;
	char * PolicyFilename;
};

static struct Policy_Filelist Policy_File_List[] =
{
	{"AUDI","/etc/policy/local/AuditFile"},
	{"DACF","/etc/policy/local/DacFile"},
	{"SUBL","/etc/policy/local/SubLabelFile"},
	{"OBJL","/etc/policy/local/ObjLabelFile"},
	{"AUUL","/etc/policy/local/AuthUserFile"},
	{"UIDL","/etc/policy/local/UserID"},
	{"PRIF","/etc/policy/local/PriListFile"},
	{NULL,NULL}
};


static inline int IsAValidChar(char c)
{
	if((c=='\t')||(c=='\n')||(c=='\0')||(c=='\r'))
	{
		return 0;
	}
	return 1;
}
/*
int InitPolicyLib()
{
	logic_baselib_init();
	register_policy_lib("SUBL",SUB_LABEL_desc,&sublabel_policy_ops);
	register_policy_lib("OBJL",OBJ_LABEL_desc,&objlabel_policy_ops);
	register_policy_lib("DACF",DAC_desc,&dac_policy_ops);
	register_policy_lib("AUDI",AUDIT_POLICY_desc,&audit_policy_ops);
	register_policy_lib("AUUL",AuthUser_desc,&authuser_policy_ops);
	return 0;
}
*/
int MakePackage(char * policytype, BYTE * string,void * Package_Data, 
	int string_len)
{
	char buffer[MAX_LINE_LEN];
	int i,j;
	char * ret;
	POLICY_HEAD * policy_head;
	BYTE * Data;
	int offset=0;
	int stroffset=0;
	int retval;
	int recordnum=0;

//     decide the policies's format

	void * lib;
	void * struct_template;

	i=0;
	string[string_len]=0;
	lib=find_policy_lib(policytype);
        if((lib==NULL)&&(IS_ERR(lib)))
		return lib;
       	struct_template = get_policy_struct(lib);

	// gen a policy head
	Data = Package_Data;
	policy_head=(POLICY_HEAD *)Data;
	memcpy(&(policy_head->PolicyType),policytype,4);
	offset = sizeof(POLICY_HEAD);
	while(stroffset<string_len)
	{
		
		retval=text_2_blob(string,Data+offset,struct_template,
			&stroffset);
		if(retval<0)
		{
			printk("read struct from string err!\n");
			return retval;
		}
		offset+=retval;
		recordnum++;
 		while(!IsAValidChar(string[stroffset]))
		{
			stroffset++;
		}
	}
	policy_head->RecordNum=recordnum;

	return offset;

}

int LoadTxtPolicyFile(char * filename,char * policytype,BYTE ** buf)
{
	// open file and read all the data
	struct stat statbuf;
	int recordsize;
	BYTE * buffer, *databuffer;
	int fd;
	int retval;
	
	fd=open(filename,O_RDONLY);
	if(fd<0)
	{
		printf("can't open txt policy file! \n");
		return -EACCES;
	}
	
	if(fstat(fd,&statbuf)<0)

	{
		printf("fstat error\n");
		return -2;
	}	
	recordsize = statbuf.st_size;

	buffer = (BYTE  *)kmalloc(recordsize+1,GFP_KERNEL);
	if(buffer == NULL)
		return -ENOMEM;
	databuffer = (BYTE  *)kmalloc(recordsize*2,GFP_KERNEL);
	if(databuffer == NULL)
		return -ENOMEM;
	if(read(fd,buffer,recordsize)!=	recordsize)
	{
		printf("read protocolirecord error! \n");
		return -EINVAL;
	}

	close(fd);
	retval = MakePackage(policytype,buffer,databuffer,recordsize);
	if(retval<0)
	{
		printk("convert %s policy error!\n",policytype);
		return retval;
	}
	free(buffer);

	buffer = (BYTE  *)kmalloc(retval,GFP_KERNEL);
	if(buffer == NULL)
		return -ENOMEM;
	
	memcpy(buffer,databuffer,retval);
	free(databuffer);
	*buf=buffer;
	return retval;
}

void * BuildPolicy(char * policystring,char * policytype)
{
	void * struct_template;
	int size,retval;
	void * policy;
	char Buffer[1000];
	struct_template=logic_get_policy_struct(policytype);
	if(struct_template == NULL)
		return NULL;


	int stroffset=0;
	retval=text_2_blob(policystring,Buffer,struct_template,&stroffset);
	if(retval<0)
	{
		return NULL;
	}
	size=alloc_struct(&policy,struct_template);

	if(size<=0)
		return NULL;
	retval=blob_2_struct(Buffer,policy,struct_template);
	if(retval<0)
	{
		free(policy);
		return NULL;
	}
	return policy;
}

int OutPutPolicy(void * policy,char * policytype)
{
	void * struct_template;
	char Text[4096];
	char Buffer[4096];
	int retval;
	int stroffset=0;
	
	struct_template=logic_get_policy_struct(policytype);
	if(struct_template == NULL)
	{
		printf("Output policy Error! invalid struct description");
		return NULL;
	}
	if(policy==NULL)
	{
		printf("Output policy Error! no policy data");
		return NULL;
	}
	if(IS_ERR(policy))
	{
		printf("Output policy Error! invalid policy data");
		return policy;
	}	
	retval=	struct_2_blob(policy,Buffer,struct_template);
	if(retval<=0)
		return retval;
	
	retval=	blob_2_text(Buffer,Text,struct_template,&stroffset);
	if(retval<=0)
		return retval;
	Text[stroffset]=0;
	printf("%s\n",Text);
	return retval;
}

int ExportPolicyPackage(void ** policypackage,char * policytype,int size)
{

	int recordsize;
	BYTE * buffer, *databuffer;
	int retval;
	POLICY_HEAD * policy_head;
	POLICY_LIB *lib;
	struct trust_policy_ops * ops;
	void * policy;
	void * struct_template;

	int offset=0;
	int recordnum=0;
	if(size<sizeof(POLICY_HEAD))
		return -EINVAL;

	databuffer = (BYTE  *)kmalloc(size+POLICY_MAX_BUF,GFP_KERNEL);
	if(databuffer == NULL)
		return -ENOMEM;
	offset=sizeof(POLICY_HEAD);
	lib=find_policy_lib(policytype);
	if(lib==NULL)
		return -EINVAL;
	ops=lib->policy_ops;
	struct_template=lib->struct_template;
	
	policy=ops->getnext(lib);
	while(policy!=NULL)
	{
		retval=struct_2_blob(policy,databuffer+offset,struct_template);
		if(retval+offset>size)
		{
			if(offset==sizeof(POLICY_HEAD))
			{
				free(databuffer);
				return -ENOSPC;
			}
			break;
		}
		recordnum++;
		offset+=retval;
		if(retval+offset==size)
		{
			break;
		}
	}
	if(offset==sizeof(POLICY_HEAD))
	{
		free(databuffer);
		return 0;
	}
	buffer = (BYTE  *)kmalloc(offset,GFP_KERNEL);
	memcpy(buffer,databuffer,offset);
	free(databuffer);
	*policypackage=buffer;
	policy_head=(POLICY_HEAD *)buffer;
	memcpy(&(policy_head->PolicyType),policytype,
		sizeof(policy_head->PolicyType));
	policy_head->RecordNum=recordnum;
	return offset;
}

int ExportPolicyToFile(char * filename,char * policytype)
{
	// open file and read all the data
	int fd;
	int recordsize;
	BYTE * buffer;
	int retval;
	POLICY_HEAD * policy_head;
	POLICY_LIB *lib;
	struct trust_policy_ops * ops;
	void * policy;
	void * struct_template;

	int offset=0;
	int recordnum=0;

	fd=open(filename,O_WRONLY|O_TRUNC|O_CREAT,00666);
	if(fd<0)
	{
		printk("can't open policy file%s! \n",filename);
		return -EACCES;
	}

	buffer = (BYTE  *)kmalloc(POLICY_MAX_BUF,GFP_KERNEL);
	if(buffer == NULL)
	{
		close(fd);
		return -ENOMEM;
	}

	offset=sizeof(POLICY_HEAD);

	lib=find_policy_lib(policytype);
	if(lib==NULL)
	{
		close(fd);
		free(buffer);
		return -EINVAL;
	}

	ops=lib->policy_ops;
	struct_template=lib->struct_template;
	
	policy=ops->getfirst(lib);
	lseek(fd,offset,SEEK_SET);
	while(policy!=NULL)
	{
		recordsize=struct_2_blob(policy,buffer,struct_template);
		if(recordsize<0)
		{
			close(fd);
			free(buffer);
			return recordsize;
		}
		retval=write(fd,buffer,recordsize);
		if(retval!=recordsize)
		{
			close(fd);
			free(buffer);
			return -EIO;
		}
		offset+=retval;
		recordnum++;
		policy=ops->getnext(lib);
	}
	memset(buffer,0,sizeof(POLICY_HEAD));
	policy_head=(POLICY_HEAD *)buffer;
	memcpy(&(policy_head->PolicyType),policytype,
		sizeof(policy_head->PolicyType));
	policy_head->RecordNum=recordnum;
	lseek(fd,0,SEEK_SET);
	write(fd,buffer,sizeof(POLICY_HEAD));
	close(fd);
	free(buffer);
	return offset;
}

char * GetPolicyFileName(char * policytype)
{
	int i=0;
	struct Policy_Filelist * filelist=NULL;

	for(i=0;i<100;i++)
	{
		filelist=&(Policy_File_List[i]);
		if(filelist->PolicyType == NULL)
			return NULL;
		if(strncmp(filelist->PolicyType,policytype,4)==0)
		{
			filelist=&(Policy_File_List[i]);
			break;
		}
	}
	return filelist->PolicyFilename;
}
int LoadBinFile(char * filename,BYTE ** buf)
{
	// open file and read all the data
	struct stat statbuf;
	int recordsize;
	BYTE * buffer;
	int fd;
	int retval;
	
	fd=open(filename,O_RDONLY);
	if(fd<0)
	{
		printf("can't open txt policy file! \n");
		return -EACCES;
	}
	
	if(fstat(fd,&statbuf)<0)

	{
		printf("fstat error\n");
		return -2;
	}	
	recordsize = statbuf.st_size;

	buffer = (BYTE  *)kmalloc(recordsize,GFP_KERNEL);
	if(buffer == NULL)
		return -ENOMEM;
	if(read(fd,buffer,recordsize)!=	recordsize)
	{
		printf("read protocolirecord error! \n");
		return -EINVAL;
	}
	close(fd);
	*buf=buffer;
	return recordsize;
}
/*
int LoadPolicy(char * policytype)
{
	char * filename;
	BYTE * buffer;
	int retval;

	filename=GetPolicyFileName(policytype);
	if(filename==NULL)
		return -EINVAL;
	retval=LoadBinFile(filename,&buffer);
	if(retval<0)
		return retval;
	retval=LoadPolicyData(buffer);	
	kfree(buffer);
	return retval;
}
*/
int LoadPolicy(char * policytype)
{
	char filename[128];

	
	sprintf(filename,"./lib/%s.lib",policytype);
	return	LoadPolicyFromFile(filename,policytype);
}

int ExportPolicy(char * policytype)
{
	char filename[128];
	
	sprintf(filename,"./lib/%s.lib",policytype);
	return ExportPolicyToFile(filename,policytype);

}

int LoadPolicyFromFile(char * filename,char * policytype)
{
	BYTE * buffer;
	int retval;

	if(filename==NULL)
		return -EINVAL;
	retval=LoadBinFile(filename,&buffer);
	if(retval<0)
		return retval;
	retval=LoadPolicyData(buffer);	
	kfree(buffer);
	return retval;
}

int UpdatePolicyFile(char * policytype)
{
	char * filename;
	filename=GetPolicyFileName(policytype);
	if(filename==NULL)
		return -EINVAL;
	return ExportPolicyToFile(filename,policytype);
}

