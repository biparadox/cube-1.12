
//#include <sys/time.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/fs.h>

#include "include/data_type.h"
#include "include/extern_struct.h"
#include "include/extern_struct_desc.h"
#include "include/extern_defno.h"
#include "include/struct_deal.h"
#include "attrlist.h"
#include "logic_baselib.h"
#include "logic_compare.h"
#include "typefind_defno.h"

//#define OS210_TEST

time_t APTtoTime_t(APTIME *apttime);
AUDIT_POLICY * ProbeList; 
struct timer_list AuditControlTimer;
int AuditReset(void);

static void interval_audit_control()
{
	const int interval = 1000*60;  // 10 s

	AuditControlTimer.expires += interval;
	AuditReset();
	mod_timer(&AuditControlTimer,AuditControlTimer.expires);
}

int audit_timer_init()
{
	extern volatile unsigned long jiffies;
	const int interval = 1000*60;  // 10 s

//	printk("os210:begin to init audit timer!\n");
	init_timer(&AuditControlTimer);
	AuditControlTimer.expires=jiffies+interval;
	AuditControlTimer.data=0;
	AuditControlTimer.function = interval_audit_control;

	add_timer(&AuditControlTimer);	
	return 0;
}
void audit_timer_destroy(void)
{
//	printk("os210:begin to destroy audit timer!\n");
	del_timer(&AuditControlTimer);
}


int AuditInit(void)
{

	int i;
	int probenum=0;
	printk("os210:begin to init audit list!\n");
	// Init the AuditProbeList table;
	ProbeList = (AUDIT_POLICY *)kmalloc(sizeof(AUDIT_POLICY) *AUDIT_PROBE_END,GFP_KERNEL);
	if(ProbeList == NULL)
	{
		printk("os210: can't alloc Audit space!\n");
		return -ENOMEM;
	}
	memset(ProbeList,0,sizeof(AUDIT_POLICY)*AUDIT_PROBE_END);

	// get the auditpolicylist;
	struct list_head * record_list,*record_head;
	Record_List * record_elem;
	AUDIT_POLICY * auditpolicy;

//	record_head = &(os210_sec_core->audit_list.list);
//	record_list=	record_head->next;

	Record_List * record;
	AUDIT_POLICY * policy;

	POLICY_LIB * lib;
	lib=find_policy_lib("AUDI");
	record = lib->policy_ops->getfirst(lib);

	while(record != NULL)
	{
		policy = (AUDIT_POLICY *)(record->record);
		record = lib->policy_ops->getnext(lib);
		if(policy!=NULL)
		{
			if((policy->NodeID >=0) &&
				(policy->NodeID<AUDIT_PROBE_END))
			{
				memcpy(&ProbeList[policy->NodeID],
					policy,sizeof(AUDIT_POLICY));
					probenum++;
				AUDIT_POLICY * probeinfo;
				probeinfo=&ProbeList[policy->NodeID];
//				printk("NodeID %d On_Off %x iType%ld \n",
//					probeinfo->NodeID,probeinfo->On_Off,
//					probeinfo->iType);
			}
			else
			{
				printk("Error Probe No %d!\n",policy->NodeID);
			}
		}
		if(probenum>(AUDIT_PROBE_END))
		{
			printk("too many audit policies!\n");
			return -EINVAL;
		}
	}
	AuditReset();
	return 0;
}

int AuditReset(void)
{

	Record_List * record;
	AUDIT_POLICY * policy;
	AUDIT_POLICY * probeinfo;
	struct timeval thetime;
  	time_t time,btime,etime;

	do_gettimeofday(&thetime);
  	time = thetime.tv_sec;

	POLICY_LIB * lib;
	lib=find_policy_lib("AUDI");
	record = lib->policy_ops->getfirst(lib);

	while(record != NULL)
	{
		policy = (AUDIT_POLICY *)(record->record);
		record = lib->policy_ops->getnext(lib);
//		printk("get an audit policy! NodeID %d iType %d On_Off %x\n",
//			policy->NodeID,policy->iType,policy->On_Off);
//		printk("policy reserved val is %d\n",policy->Reserved);
//		if(policy->NodeID > AUDIT_PROBE_END)
//		{
//			printk("illegal Audit ProbeNo range.\n");
//			break;
//		}
		btime = APTtoTime_t(&policy->BeginTime);
		etime = APTtoTime_t(&policy->EndTime);
//		btime = policy->BeginTime;
//		etime = policy->EndTime;
//		printk("\nbtime--%ld,time--%ld,etime--%ld,\n",btime,time,etime);
		if((time>btime) && (time <etime))
		{
			probeinfo=&(ProbeList[policy->NodeID]);
			probeinfo->On_Off = policy->On_Off;
//			
//			printk("NodeID %d On_Off %x iType%d \n",
//				probeinfo->NodeID,probeinfo->On_Off,
//				probeinfo->iType);
		}
		else
		{
			//if time is not in the timeval,we should off all the 
			//other probe and only keep the normal audit in the
			//FAIL and TRUSTFAIL mask
			ProbeList[policy->NodeID].On_Off = AUDIT_PROBE_OFF;
//			ProbeList[policy->Reserved].On_Off += 
//				(AUDIT_PROBE_ONFAIL|AUDIT_PROBE_ONTRUSTFAIL)
//				<<16;
		}
       }
	return 0;
}

static int my_atoi(const char *name)
{
    int val = 0;

    for (;; name++) {
	switch (*name) {
	    case '0' ... '9':
		val = 10*val+(*name-'0');
		break;
	    default:
		return val;
	}
    }
}

time_t APTtoTime_t(APTIME *apttime)
{
	int year,month,day,hour,min,second;
	unsigned char *buff;
	buff= (unsigned char *)kmalloc(5,GFP_KERNEL);
	memset(buff,0,5);
	memcpy(buff,apttime->Year,4);
	year=my_atoi(buff);
	memset(buff,0,5);
	memcpy(buff,apttime->Month,2);
	month=my_atoi(buff);
	memcpy(buff,apttime->Day,2);
	day=my_atoi(buff);
	memcpy(buff,apttime->Hour,2);
	hour=my_atoi(buff);
	memcpy(buff,apttime->Min,2);
	min=my_atoi(buff);
	memcpy(buff,apttime->Second,2);
	second=my_atoi(buff);
	kfree(buff);
//	printk("date:%d %d %d %d %d %d\n",year,month,day,hour,min,second);
	return (mktime(year,month,day,hour,min,second)-28800);
}

#ifdef OS210_TEST

#define DEBUG_HOOK  AUDIT_PROBE_EXEC_FILE
#define DEBUG_INODE 570137

//wdh modify20111115
int AuditProbe(int ProbeNo, void * obj, int mode,int Bret)
{
	// place the task pid and the file's inode to the reserved[8] 
  struct tagReserved
  {
		UINT16  pid;   // pid or uid
		UINT16  superblock;
		UINT32	ino;
  } __attribute((packed))__;
 struct tagReserved * Reserved;
	
  AUDIT_POLICY * probeinfo;
  AUDIT_RECORD * Audit_Record;
  struct timeval thetime;
  time_t time;
  int retval;

//name define start  
  char *subname;
  char *objname;
  int sub_length=0;
  int obj_length=0;
  int expandflag=0;
  UINT16 audit_type=0;
//name define end
  		 
// deal with the audit switch,
// judge if it is an except audit,a key audit or a normal audit

  int auditmask;
  int i;
//  if(ProbeNo == AUDIT_PROBE_GET_FILE)
//	  printk("AUDIT_PROBE_GET_FILE\n");
  // check if the probe is on	
  probeinfo = &(ProbeList[ProbeNo]);
	
if(ProbeNo==DEBUG_HOOK)
{
	struct inode * i_test=(struct inode *)obj; 
	if(i_test->i_ino==DEBUG_INODE)
	{	
		printk("Get Inode start  %x %d switch %x bret %x\n",
			obj,i_test->i_ino,probeinfo->On_Off,Bret);
		 
	}
}

  if(probeinfo->On_Off == AUDIT_PROBE_OFF)//8.1
	return AUDIT_PROBE_OFF;

  int brettest=Bret;

  audit_type=EXCEPT_AUDIT_RECORD;
  // find the audit type
  for(i=0;i<3;i++)
  {
	  if(probeinfo->On_Off & brettest)
		  break;
	  brettest<<=8;
	  audit_type--;	
  }

if(ProbeNo==DEBUG_HOOK)
{
	struct inode * i_test=(struct inode *)obj; 
	if(i_test->i_ino==DEBUG_INODE)
	{	
		printk("Get Inode start 2  %x %d i=%d \n",
			obj,i_test->i_ino,i);
	}
}
  // this audit information do not audit 
  if(i==3)
  	return 0;
  // judge if we should make expand record
  expandflag=probeinfo->On_Off & brettest;
  // generate the audit record	

if(ProbeNo==DEBUG_HOOK)
{
	struct inode * i_test=(struct inode *)obj; 
	if(i_test->i_ino==DEBUG_INODE)
	{	
		printk("Get Inode start 3  %x %d\n",
			obj,i_test->i_ino);
	}
}


  // generate the audit record head 
  Audit_Record = kmalloc(sizeof(AUDIT_RECORD),GFP_KERNEL);
  if(!Audit_Record)
  {
	  printk("alloc Audit_Record err!\n");
	  return -ENOMEM;
  }
  memset(Audit_Record, 0, sizeof(AUDIT_RECORD));

  // fill the Audit Record
  Audit_Record->iType = probeinfo->iType;	
  Audit_Record->NodeID = ProbeNo;	//8.1syb

/*if(ProbeNo==AUDIT_PROBE_GET_INODE)
{
	printk("NodeID %d On_Off %x iType%d \n",
		probeinfo->NodeID,probeinfo->On_Off,
		probeinfo->iType);
}*/

  // get audit's time
  do_gettimeofday(&thetime);
  time = thetime.tv_sec;
  Audit_Record->Time  = time;

  // alloc the auditrecord's name space
 
	subname=kmalloc(512,GFP_KERNEL);
	if(subname==NULL)
		return -ENOMEM;	
	objname=kmalloc(1024,GFP_KERNEL);
	if(objname==NULL)
		return -ENOMEM;		
	memset(subname,0,512);
	memset(objname,0,1024);

  // get the subject's info
  switch(ProbeNo)
  {
	case 	AUDIT_PROBE_SYS_START:
		strcpy(Audit_Record->sSubName+2,"Alexander");
		*(UINT16 *)(Audit_Record->sSubName)=strlen("Alexander");
		break;
	case 	AUDIT_PROBE_INODE_INITMARK:
		break;
	case 	AUDIT_PROBE_FILE_INITMARK:
		break;
	case 	AUDIT_PROBE_TASK_INITMARK:
 		sub_length = audit_get_task_info(obj, subname, Audit_Record);
		break;
	case	AUDIT_PROBE_CREATE_INODE:
	case	AUDIT_PROBE_OPEN_FILE:
	case	AUDIT_PROBE_READ_FILE:
	case	AUDIT_PROBE_WRITE_FILE:
	case	AUDIT_PROBE_EXEC_FILE:
	case	AUDIT_PROBE_DELETE_FILE:
	case	AUDIT_PROBE_DELETE_DIR:
	case	AUDIT_PROBE_CREATE_DIR:
	case	AUDIT_PROBE_SET_INODE_ATTR:
	case	AUDIT_PROBE_GET_INODE_ATTR:
	case	AUDIT_PROBE_MKNOD:
	case	AUDIT_PROBE_RENAME:
	case	AUDIT_PROBE_NETWORK_ACCESS:
	case	AUDIT_PROBE_READ_INODE:
	case	AUDIT_PROBE_WRITE_INODE:
	case	AUDIT_PROBE_FORK:
	case	AUDIT_PROBE_EXIT:
	case	AUDIT_PROBE_EXITGROUP:
	case	AUDIT_PROBE_LOGIN:
	case	AUDIT_PROBE_LOGOUT:
	case	AUDIT_PROBE_MSG_QUEUE_ASSOCIATE:
	case	AUDIT_PROBE_MSG_QUEUE_MSGCTL:
	case	AUDIT_PROBE_MSG_QUEUE_MSGSND:
	case	AUDIT_PROBE_MSG_QUEUE_MSGRCV:	
	case	AUDIT_PROBE_SHM_ASSOCIATE:
	case	AUDIT_PROBE_SHM_SHMCTL:
	case	AUDIT_PROBE_SHM_SHMAT:
	case	AUDIT_PROBE_SEM_ASSOCIATE:
	case	AUDIT_PROBE_SEM_SEMCTL:
	case	AUDIT_PROBE_SEM_SEMOP:
	case	AUDIT_PROBE_SOCKET_CREATE:
	case	AUDIT_PROBE_SOCKET_BIND:
	case	AUDIT_PROBE_SOCKET_IOCTL:
	case	AUDIT_PROBE_SOCKET_CONNECT:
	case	AUDIT_PROBE_SOCKET_LISTEN:
	case	AUDIT_PROBE_SOCKET_ACCEPT:
	case	AUDIT_PROBE_SOCKET_SENDMSG:
	case	AUDIT_PROBE_SOCKET_RECVMSG:
	case	AUDIT_PROBE_SOCKET_SETSOCKOPT:
	case	AUDIT_PROBE_SOCKET_GETSOCKOPT:
	case	AUDIT_PROBE_GET_INODE:
	case	AUDIT_PROBE_GET_FILE:
	case	AUDIT_PROBE_REPEAT_READ:
	case	AUDIT_PROBE_REPEAT_WRITE:
	case	AUDIT_PROBE_EXEC_REMARK:
		if(ProbeNo==AUDIT_PROBE_GET_FILE)
		{
			printk("AuditProbe:SubName= %s pid %d\n",Audit_Record->sSubName+2,current->pid);
		}
		sub_length = audit_get_task_info(get_curr_sec(), 
			subname, Audit_Record);
		if(sub_length < 0)
		{
			kfree(Audit_Record);
			kfree(subname);
			kfree(objname);
			return sub_length;
		}
		break;
	case	AUDIT_PROBE_SETUID:
		{
	  		SUB_LABEL *task_label;
			int length;
			task_label=(SUB_LABEL *)obj;
	  		memset(Audit_Record->sSubName,0,20);
	  		length = task_label->SubName.length;
	  		memset(subname,0,length+1);
	  		memcpy(subname, task_label->SubName.String,length);
	  		if(length >18)
	  		{ 
 		  		memcpy(Audit_Record->sSubName,&length,2);
		  		memcpy(Audit_Record->sSubName+2,
					subname+length-18,18);
			}
			else
			{
 		  		memcpy(Audit_Record->sSubName,&length,2);
		  		memcpy(Audit_Record->sSubName+2,subname,length);
			}
	  		memcpy(&(Audit_Record->SubLabel),
				&(task_label->SubLabel),sizeof(MAC_LABEL));
	  		Audit_Record->SubType = task_label->SubType;
			Reserved = (struct tagReserved *)
				(Audit_Record->Reserved);
	  		Reserved->pid = current->pid;
		}
		break;
	case	AUDIT_PROBE_END:
	default:
		break;
			
  }
  struct task_struct  * p;
//  get the object's info
  switch(ProbeNo)
  {
	case 	AUDIT_PROBE_SYS_START:
		break;
	case 	AUDIT_PROBE_TASK_INITMARK:
		strcpy(Audit_Record->sObjName+2,"taskinitmark");
		break;

	case	AUDIT_PROBE_FILE_INITMARK:
		break;
	case	AUDIT_PROBE_CREATE_INODE:
	case	AUDIT_PROBE_CREATE_DIR:
	case	AUDIT_PROBE_NETWORK_ACCESS:
		audit_get_filename_info((char *)obj, Audit_Record);
		obj_length = strlen((char *)obj);
		memcpy(objname, (char *)obj, obj_length);	
		break;
	case	AUDIT_PROBE_OPEN_FILE:
	case	AUDIT_PROBE_READ_FILE:
	case	AUDIT_PROBE_WRITE_FILE:
	case	AUDIT_PROBE_EXEC_FILE:
//	case	AUDIT_PROBE_DELETE_DIR:
//	case	AUDIT_PROBE_DELETE_FILE:
	case	AUDIT_PROBE_GET_FILE:
	case	AUDIT_PROBE_REPEAT_READ:
	case	AUDIT_PROBE_REPEAT_WRITE:
		obj_length = audit_get_file_info((struct file*)obj, objname, Audit_Record);
  		if(ProbeNo==AUDIT_PROBE_GET_FILE)
  		{
		//	inode_sec=(INODE_SEC *)((struct inode *) obj)->i_security;	
		 	printk("audit probe: probe get file: file %x\n",
				obj);
		}
		if(obj_length < 0)
		{
			kfree(Audit_Record);
			kfree(subname);
			kfree(objname);
			return obj_length;
		}
		Reserved = (struct tagReserved *)(Audit_Record->Reserved);
	  	Reserved->ino = ((struct file *)obj)->f_dentry->d_inode->i_ino;
		break;
	case	AUDIT_PROBE_INODE_INITMARK:
	case	AUDIT_PROBE_GET_INODE:
	case	AUDIT_PROBE_SET_INODE_ATTR:
	case	AUDIT_PROBE_GET_INODE_ATTR:
	case	AUDIT_PROBE_READ_INODE:
	case	AUDIT_PROBE_DELETE_DIR:
	case	AUDIT_PROBE_DELETE_FILE:
	case	AUDIT_PROBE_RENAME:
	case	AUDIT_PROBE_WRITE_INODE:
		obj_length = audit_get_inode_info((struct inode *)obj, 
			 objname, Audit_Record);
  		if(ProbeNo==AUDIT_PROBE_GET_INODE)
  		{
		//	inode_sec=(INODE_SEC *)((struct inode *) obj)->i_security;	
		  //	printk("audit probe: probe get inode obj name %s,obj_length:%d, bret %x!\n",objname,obj_length,Bret);
  		 
	  		if(((struct inode *)obj)->i_ino==DEBUG_INODE)
			{	
//				if(ProbeNo==AUDIT_PROBE_GET_INODE)
				printk("audit inode name: %x %s length:%d\n",
					&objname,objname,obj_length);
				printk("name in audit record: %s \n",
					Audit_Record->sObjName+2);
			}
		}
		if(obj_length < 0)
		{
			printk("AuditProbe:get a wrong inode!\n");
			kfree(Audit_Record);
			kfree(subname);
			kfree(objname);
			return obj_length;
		}
	  	//Reserved.ino = ((struct inode *)obj)->i_ino;
		break;
	case	AUDIT_PROBE_MKNOD:
		break;
	case	AUDIT_PROBE_FORK:
	  	p = (struct task_struct *)obj; 
	  	if(p!=NULL)
		{
//		  printk("PROBE FORK: task %x %d!\n",p,p->pid);
	  	  Reserved = (struct tagReserved *)(Audit_Record->Reserved);
		  Reserved->ino = p->pid;
		}
    	 	else
		{
//		  printk("PROBE FORK: task %x invalid!\n",p);
		}
		break;
	case	AUDIT_PROBE_SETUID:
		{
          		TASK_SEC *task_sec;
	  		SUB_LABEL *task_label;
			int length;
			task_sec=get_curr_sec() ;
			task_label=&(task_sec->task_label);
	  		memset(Audit_Record->sObjName,0,20);
	  		length = task_label->SubName.length;
	  		memset(objname,0,length+1);
	  		memcpy(objname, task_label->SubName.String,length);
	  		if(length >18)
	  		{ 
 		  		memcpy(Audit_Record->sObjName,&length,2);
		  		memcpy(Audit_Record->sObjName+2,
					objname+length-18,18);
			}
			else
			{
 		  		memcpy(Audit_Record->sObjName,&length,2);
		  		memcpy(Audit_Record->sObjName+2,objname,length);
			}
	  		memcpy(&(Audit_Record->ObjLabel),
				&(task_label->SubLabel),sizeof(MAC_LABEL));
	  		Audit_Record->ObjType = task_label->SubType;
		}
		break;
	case	AUDIT_PROBE_EXIT:
	case	AUDIT_PROBE_EXITGROUP:
	case	AUDIT_PROBE_LOGIN:
	case	AUDIT_PROBE_LOGOUT:
	case	AUDIT_PROBE_MSG_QUEUE_ASSOCIATE:
	case	AUDIT_PROBE_MSG_QUEUE_MSGCTL:
	case	AUDIT_PROBE_MSG_QUEUE_MSGSND:
	case	AUDIT_PROBE_MSG_QUEUE_MSGRCV:	
	case	AUDIT_PROBE_SHM_ASSOCIATE:
	case	AUDIT_PROBE_SHM_SHMCTL:
	case	AUDIT_PROBE_SHM_SHMAT:
	case	AUDIT_PROBE_SEM_ASSOCIATE:
	case	AUDIT_PROBE_SEM_SEMCTL:
	case	AUDIT_PROBE_SEM_SEMOP:
	case	AUDIT_PROBE_SOCKET_CREATE:
	case	AUDIT_PROBE_SOCKET_BIND:
	case	AUDIT_PROBE_SOCKET_IOCTL:
	case	AUDIT_PROBE_SOCKET_CONNECT:
	case	AUDIT_PROBE_SOCKET_LISTEN:
	case	AUDIT_PROBE_SOCKET_ACCEPT:
	case	AUDIT_PROBE_SOCKET_SENDMSG:
	case	AUDIT_PROBE_SOCKET_RECVMSG:
	case	AUDIT_PROBE_SOCKET_SETSOCKOPT:
	case	AUDIT_PROBE_SOCKET_GETSOCKOPT:
	case	AUDIT_PROBE_EXEC_REMARK:
	case	AUDIT_PROBE_END:
	default:
		break;
}
  Audit_Record->Bret = Bret; 


//  Audit_Record->Bret = probeinfo->Bret*256+ Bret; 
  
//  memcpy(Audit_Record->Reserved,&Reserved,8);
  
// build the expand package;

#define EXPANDDATALEN  60
#define RECORDNAMELEN  18
#define MAXEXPANDNUM   30

	int expandrecordnum=0;
	int subexpandnum=0;
	int objexpandnum=0;
	BYTE * expandrecordbuf;
	if(expandflag)
	{
//		printk("compute expand flag %d %d!\n",sub_length,obj_length);
		if(sub_length>RECORDNAMELEN)
			subexpandnum=(sub_length-RECORDNAMELEN)/EXPANDDATALEN+1;
		if(obj_length>RECORDNAMELEN)
			objexpandnum=(obj_length-RECORDNAMELEN)/EXPANDDATALEN+1;
		expandrecordnum=subexpandnum+objexpandnum;
		if(expandrecordnum>0)
		{
			expandrecordbuf=kmalloc(
				expandrecordnum*sizeof(AUDIT_EXPANDRECORD),
				GFP_KERNEL);
			if(expandrecordbuf==NULL)
				return -ENOMEM;
			Audit_Record->iType |= (EXPAND_AUDIT_RECORD<<8);
//			printk("audit %d has expand_record %d iType %x!\n",
//				ProbeNo,expandrecordnum,Audit_Record->iType);
		}
  		if(subexpandnum>0)
  		{

  			//edit sub expandrecord
  			ExAuditBag(expandrecordbuf,audit_type,sub_length,subname);
  		}
  		if(objexpandnum>0)
  		{

  			//edit obj expandrecord
  			ExAuditBag(expandrecordbuf+
				subexpandnum*sizeof(AUDIT_EXPANDRECORD),
				audit_type,obj_length,objname);
  		}
  	}	
  
if(ProbeNo==AUDIT_PROBE_INODE_INITMARK)
{
//	printk("probe inode initmark name %s\n",Audit_Record->sObjName+2);
}
//wdh modify  
  if(audit_type==NORMAL_AUDIT_RECORD)
  {      
//	printk("send audit record type %d Probe %d\n",
//		Audit_Record->iType,Audit_Record->NodeID);
  	maninfo_add_audit_item(Audit_Record);//发送审计信息给信息管理信息模块
	for(i=0;i<expandrecordnum;i++)
	{
//		printk("Send NormalExpand record %d!\n",i);
		maninfo_add_audit_item(expandrecordbuf
			+sizeof(AUDIT_EXPANDRECORD)*i);
	}
  }
  else if((audit_type==KEY_AUDIT_RECORD)||(audit_type==EXCEPT_AUDIT_RECORD))
  {
//        printk("send kaudit record type %d Probe %d\n", 
 // 		Audit_Record->iType,Audit_Record->NodeID);
    	kmaninfo_add_audit_item(Audit_Record);//发送审计信息给信息管理信息模块
	for(i=0;i<expandrecordnum;i++)
	{
//		printk("Send KeyExpand record %d %s!\n",i,objname);
		kmaninfo_add_audit_item(expandrecordbuf
			+sizeof(AUDIT_EXPANDRECORD)*i);
	}
  }
//wdh end 
  kfree(subname);
  kfree(objname); 
  return 0;
}

# define DAUDIT_WRITE_DENY                      1
# define DAUDIT_IMMUTABLE_DENY                  2
# define DAUDIT_INODE_PERMISSION_DENY           3
# define DAUDIT_DEVCGROUP_INODE_PERMISSION_DENY 4
# define DAUDIT_PERMISSION_SUCC                 5
int DAC_AuditProbe(int ProbeNo, void * obj, int mode,int Bret)
{
	// place the task pid and the file's inode to the reserved[8] 
  struct tagReserved
  {
		UINT16  pid;   // pid or uid
		UINT16  superblock;
		UINT32	ino;
  } __attribute((packed))__;
 struct tagReserved * Reserved;
	
  AUDIT_POLICY * probeinfo;
  AUDIT_RECORD * Audit_Record;
  struct timeval thetime;
  time_t time;
  int retval;

//name define start  
  char *subname;
  char *objname;
  int sub_length=0;
  int obj_length=0;
  int expandflag=0;
  UINT16 audit_type=0;
//name define end
  		 
// deal with the audit switch,
// judge if it is an except audit,a key audit or a normal audit

  int auditmask;
  int i;

  // check if the probe is on	
	



  // generate the audit record head 
  struct inode* inode;
  inode = (struct inode*)obj;
  Audit_Record = kmalloc(sizeof(AUDIT_RECORD),GFP_KERNEL);
  if(!Audit_Record)
  {
	  printk("alloc Audit_Record err!\n");
	  return -ENOMEM;
  }
  memset(Audit_Record, 0, sizeof(AUDIT_RECORD));

  // fill the Audit Record
  Audit_Record->iType = ProbeNo;	
  Audit_Record->NodeID = inode->i_ino;	//8.1syb


  // get audit's time
  do_gettimeofday(&thetime);
  time = thetime.tv_sec;
  Audit_Record->Time  = time;

  // alloc the auditrecord's name space
 
	subname=kmalloc(512,GFP_KERNEL);
	if(subname==NULL|| IS_ERR(subname))
		return -ENOMEM;	
	objname=kmalloc(1024,GFP_KERNEL);
	if(objname==NULL||IS_ERR(objname))
		return -ENOMEM;		
	memset(subname,0,512);
	memset(objname,0,1024);

	sub_length = audit_get_task_info(get_curr_sec(), 
					subname, Audit_Record);
	if(sub_length < 0)
	{
		kfree(Audit_Record);
		kfree(subname);
		kfree(objname);
		return sub_length;
	}
  // get the subject's info
  /*
   * define DAUDIT_WRITE_DENY                      1
   * define DAUDIT_IMMUTABLE_DENY                  2
   * define DAUDIT_INODE_PERMISSION_DENY           3
   * define DAUDIT_DEVCGROUP_INODE_PERMISSION_DENY 4
   * define DAUDIT_PERMISSION_SUCC                 5
   */
	
  	struct task_struct  * p;

//  get the object's info
	obj_length = audit_get_inode_info((struct inode *)obj, objname, Audit_Record);
	if(obj_length < 0)
	{
		printk("AuditProbe:get a wrong inode!\n");
		kfree(Audit_Record);
		kfree(subname);
		kfree(objname);
		return obj_length;
	}
  	Audit_Record->Bret = Bret; 


//  Audit_Record->Bret = probeinfo->Bret*256+ Bret; 
  
//  memcpy(Audit_Record->Reserved,&Reserved,8);
  
// build the expand package;

#define EXPANDDATALEN  60
#define RECORDNAMELEN  18
#define MAXEXPANDNUM   30

	int expandrecordnum=0;
	int subexpandnum=0;
	int objexpandnum=0;
	BYTE * expandrecordbuf;
	if(expandflag)
	{
//		printk("compute expand flag %d %d!\n",sub_length,obj_length);
		if(sub_length>RECORDNAMELEN)
			subexpandnum=(sub_length-RECORDNAMELEN)/EXPANDDATALEN+1;
		if(obj_length>RECORDNAMELEN)
			objexpandnum=(obj_length-RECORDNAMELEN)/EXPANDDATALEN+1;
		expandrecordnum=subexpandnum+objexpandnum;
		if(expandrecordnum>0)
		{
			expandrecordbuf=kmalloc(
				expandrecordnum*sizeof(AUDIT_EXPANDRECORD),
				GFP_KERNEL);
			if(expandrecordbuf==NULL)
				return -ENOMEM;
			Audit_Record->iType |= (EXPAND_AUDIT_RECORD<<8);
//			printk("audit %d has expand_record %d iType %x!\n",
//				ProbeNo,expandrecordnum,Audit_Record->iType);
		}
  		if(subexpandnum>0)
  		{

  			//edit sub expandrecord
  			ExAuditBag(expandrecordbuf,audit_type,sub_length,subname);
  		}
  		if(objexpandnum>0)
  		{

  			//edit obj expandrecord
  			ExAuditBag(expandrecordbuf+
				subexpandnum*sizeof(AUDIT_EXPANDRECORD),
				audit_type,obj_length,objname);
  		}
  	}	
  
  	dmaninfo_add_audit_item(Audit_Record);//发送审计信息给信息管理信息模块
	for(i=0;i<expandrecordnum;i++)
	{
//		printk("Send NormalExpand record %d!\n",i);
		dmaninfo_add_audit_item(expandrecordbuf
			+sizeof(AUDIT_EXPANDRECORD)*i);
	}
  	kfree(subname);
 	kfree(objname); 
 	return 0;
}

#define EXPANDDATALEN  60
#define RECORDNAMELEN  18
#define EXPANDDATALEN  60
#define RECORDNAMELEN  18
#define MAXEXPANDNUM   30

int ExAuditBag( BYTE * addr,UINT16 iType,UINT32 length,char *name)
{
	 struct __attribute((packed))__
         {
		  UINT16  pid;
		  UINT16  superblock;
		  UINT32	ino;
	  } Reserved;
	 
	 AUDIT_EXPANDRECORD * Audit_Expandrecord;
	 int Expand_No = 0;
	 int expandlength;
	 expandlength=length-RECORDNAMELEN;

	 while(expandlength > 0)
	 {
	 	Audit_Expandrecord = addr;
	    	memset(Audit_Expandrecord,0,sizeof(AUDIT_EXPANDRECORD));
	 
	        //KAudit_Record->NodeID
	    	if((Expand_No==0)&&(expandlength<=EXPANDDATALEN))
	    	{
	    		Audit_Expandrecord->iType = KAUDIT_TYPE_EXPAND_SINGLE;//单一扩展包
	    	 	memcpy(Audit_Expandrecord->ExpandData, name, expandlength);
	    	 	expandlength=0;
	    	}
	    	else if(Expand_No==0)
	    	{
	      		Audit_Expandrecord->iType = KAUDIT_TYPE_EXPAND_HEAD;//开头包
	       		memcpy(Audit_Expandrecord->ExpandData, name, 
				EXPANDDATALEN);
		        name+=60;
		        expandlength-=60;
	      	}
	   	else
	    	{
	    		if(expandlength>60)
	    		{
	    	 		Audit_Expandrecord->iType = KAUDIT_TYPE_EXPAND;//中间包
	         		memcpy(Audit_Expandrecord->ExpandData, name, 60);
	          		name+=60;
	          		expandlength-=60;
	    	 	}
	    	 	else
	    	 	{
	    	 		Audit_Expandrecord->iType = KAUDIT_TYPE_EXPAND_TAIL;//尾包
	    	 		memcpy(Audit_Expandrecord->ExpandData, name, expandlength);
	           		expandlength=0;
	    	 	}
	    	}
	        Audit_Expandrecord->ExpandNo = Expand_No;
	 
	        memset(&Reserved,0,sizeof(Reserved));
	        Expand_No++;
	        Audit_Expandrecord+=sizeof(AUDIT_EXPANDRECORD);
	 }
	 return 0;
}
#endif
