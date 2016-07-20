#include <stdlib.h>
#include <string.h>

#include "../include/data_type.h"
#include "../include/struct_deal.h"
#include "../include/extern_struct.h"
#include "../include/extern_struct_desc.h"
//#include "../include/logic_baselib.h"
#include "../include/logic_baselib.h"


struct Policy_Filelist
{
	char *type;
	char *name;
};

static struct Policy_Filelist Policy_File_List[] =
{
//	{"AUDI","/etc/policy/local/AuditFile"},
//	{"DACF","/etc/policy/local/DacFile"},
	{"SUBL","/etc/policy/local/SubLabelFile"},
	{"OBJL","/etc/policy/local/ObjLabelFile"},
//	{"AUUL","/etc/policy/local/AuthUserFile"},
//	{"UIDL","/etc/policy/local/UserID"},
//	{"PRIF","/etc/policy/local/PriListFile"},
	{NULL,NULL}
};

int InitPolicyLib()
{
	logic_baselib_init();
//	register_policy_lib("DACF",DAC_desc,&dac_policy_ops);
//	register_policy_lib("AUDI",AUDIT_POLICY_desc,&audit_policy_ops);
//	register_policy_lib("AUUL",AuthUser_desc,&authuser_policy_ops);
	return 0;
}

static int read_policy_local_file()
{

//#define MAXPATHNAME 256
	unsigned int  size;
	int ret;
//	char path[MAXPATHNAME];
//	mm_segment_t oldfs;
	struct dirent_policy * ptr;
	BYTE *buffer=NULL;
	struct file * ppfile= NULL;
//	char * temp;
	int i,nameoffset;
//	oldfs =get_fs();
//	set_fs(KERNEL_DS);	

	i=0;
	while(Policy_File_List[i].type != NULL)
	{
/*		
		ppfile= filp_open(Policy_File_List[i].name,O_RDONLY,0);

		if((IS_ERR(ppfile) ||ppfile==NULL))
		{
			printk("read policy %s err !",Policy_File_List[i].type);
				return -EIO;
		
		}

		size = i_size_read(ppfile->f_dentry->d_inode);
		if(!size){
//			set_fs(oldfs);
			return -EIO;
		}
		buffer =kmalloc(size,GFP_KERNEL);
		if(buffer==NULL){
	                printk("%s %d : error no memory  to allocate!\n",
				__FUNCTION__,__LINE__);
//			set_fs(oldfs);
	                return -ENOMEM;
	        }
		ret=ppfile->f_op->read(ppfile,buffer,size,&ppfile->f_pos);
		if(ret<0)
		{
			kfree(buffer);
//			set_fs(oldfs);
			return -EIO;
		}
		printk("read policy %s succeed,read %d !",Policy_File_List[i].type,size);
		ret=LoadPolicyData(buffer);
		if(ret<0)
		{
			kfree(buffer);
//			set_fs(oldfs);
			return -EIO;
		}
		printk("load policy %s succeed !",Policy_File_List[i].type);
		
		filp_close(ppfile,NULL);
		ppfile=NULL;
		kfree(buffer);*/
	}
//	set_fs(oldfs);
	return 0;

}

int main()
{
	int ret;
	InitPolicyLib();
	
	ret=read_policy_local_file();

	return 0;
	
}

