/*************************************************
*          高安全级别LINUX系统-安全策略执行模块
*
*	程序名称： 钩子框架
*	文件名  ：os210_hook.c
*	日期    ：2008-5-15
*	作者    ：李  勇(ly) 申永波
*	模块描述：钩子框架
*	修改记录：
*	修改描述：
*************************************************/



#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/reboot.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/path.h>

#include <linux/types.h>

#include <linux/binfmts.h>
#include <linux/signal.h>
#include <linux/resource.h>
#include <linux/sem.h>
#include <linux/shm.h>
#include <linux/msg.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/syscalls.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/moduleparam.h>
#include <linux/sockios.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <net/sock.h>
#include <linux/fdtable.h>
#include <linux/highmem.h>
#include <linux/cred.h>
#include <linux/binfmts.h>

#include "include/data_type.h"
#include "include/extern_struct.h"
#include "include/extern_struct_desc.h"
#include "include/extern_defno.h"
#include "include/struct_deal.h"
#include "attrlist.h"
#include "logic_baselib.h"
#include "logic_compare.h"
#include "typefind_defno.h"


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
	register_policy_lib("SUBL",SUB_LABEL_desc,&sublabel_policy_ops);
	register_policy_lib("OBJL",OBJ_LABEL_desc,&objlabel_policy_ops);
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
	mm_segment_t oldfs;
	struct dirent_policy * ptr;
	BYTE *buffer=NULL;
	struct file * ppfile= NULL;
//	char * temp;
	int i,nameoffset;
	oldfs =get_fs();
	set_fs(KERNEL_DS);	

	i=0;
	while(Policy_File_List[i].type != NULL)
	{
		ppfile= filp_open(Policy_File_List[i].name,O_RDONLY,0);

		if((IS_ERR(ppfile) ||ppfile==NULL))
		{
			printk("read policy %s err !",Policy_File_List[i].type);
				return -EIO;
		
		}

		size = i_size_read(ppfile->f_dentry->d_inode);
		if(!size){
			set_fs(oldfs);
			return -EIO;
		}
		buffer =kmalloc(size,GFP_KERNEL);
		if(buffer==NULL){
	                printk("%s %d : error no memory  to allocate!\n",
				__FUNCTION__,__LINE__);
			set_fs(oldfs);
	                return -ENOMEM;
	        }
		ret=ppfile->f_op->read(ppfile,buffer,size,&ppfile->f_pos);
		if(ret<0)
		{
			kfree(buffer);
			set_fs(oldfs);
			return -EIO;
		}
		printk("read policy %s succeed,read %d !",Policy_File_List[i].type,size);
		ret=LoadPolicyData(buffer);
		if(ret<0)
		{
			kfree(buffer);
			set_fs(oldfs);
			return -EIO;
		}
		printk("load policy %s succeed !",Policy_File_List[i].type);
		
		filp_close(ppfile,NULL);
		ppfile=NULL;
		kfree(buffer);
		i++;
	}
	set_fs(oldfs);
	return 0;

}




//#define OS210_TEST

static int __init logic_init(void)
{
	int ret;
	struct super_block * rootsb, *currsb;
	struct vfsmount * rootmnt,*currmnt;
	struct task_struct * tasks;
	printk("begin to init os210 module!\n");

	InitPolicyLib();
	ret=read_policy_local_file();
	if(ret <0)
	{
		printk("os210: load policy failed!\n");
		return ret;
	}
	printk("load policy file success!\n");
	// Init the audit policy
//	ret=AuditInit();
//	printk("finish audit init!\n");
	if(ret <0)
	{
		printk("os210: init audit policy failed!\n");
		return ret;
	}
	
//	AuditProbe(AUDIT_PROBE_SYS_START,0,KAUDIT_TYPE_SYS_START,
//		VERIFY_MAC_SUCCESS);
//	printk("send an audit message!\n");
		

	
	printk("*****os210:begin to mark the tasks!*****\n");
#ifdef OS210_TEST

	// check all processes
	char * subname;
	if((subname=(char *)kmalloc(256,GFP_KERNEL))==NULL)
		return -ENOMEM;
	ret = init_alloc_security();	
	if(ret!=NULL)
		return -EINVAL;
	for_each_process(tasks)
	{
//		label_inherittasksubname(tasks);

		printk("tasks->security %x\n",(TASK_SEC*)get_task_sec(tasks));
		printk("begin to function of exec_task_initlabel\n");
		exec_task_initlabel(tasks);
		printk("alex:init task pid %d\n",tasks->pid);
		memset(subname,0,sizeof(subname));
		ret=label_gettasksubname(tasks,subname);
		if(ret !=0)
		{
			printk("alex:the subname of process %d is %s\n",
					tasks->pid,subname);
			mark_allfile_of_process(tasks);
		}
		else
		{
			printk("alex:the process of %d has no subname\n",
					tasks->pid);
			mark_allfile_of_process(tasks);
		}
	}

	
	printk("*****os210:finish to mark the tasks******\n");
#endif

	return 0;
}

static void __exit logic_cleanup(void)
{
//	if(unregister_security(&os210_security_ops)) {
//		printk("unregister os210 security function err!\n");
//	}
//	audit_timer_destroy();
	printk("*****os210:remove the os210 module\n");
	return;	
}

security_initcall(logic_init);
module_exit(logic_cleanup);
//EXPORT_SYMBOL(AuditReset);
//EXPORT_SYMBOL(AuditProbe);
MODULE_AUTHOR("Hujun");
MODULE_DESCRIPTION("lslslslskfsejksdfajkosdflkjtjs");
MODULE_LICENSE("GPL");
