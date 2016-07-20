#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "../list.h"
#include "../attrlist.h"

#include "../../include/extern_struct.h"
#include "../../include/extern_struct_desc.h"
#include "../../include/extern_defno.h"
#include "policy_ui.h"
#include "valuename.h"

#define MAX_NAME_LEN 1024 
#define MAX_LINE_LEN 1024 
#define OS210_MAX_BUF 1024
#define KAUDIT_FILE "/etc/os210_kaudit"
#define AUDIT_FILE "/etc/os210_audit"
#define EAUDIT_FILE "/etc/os210_eaudit"

typedef struct tagAuditFilter
{
	time_t tm1;
	time_t tm2;
	BYTE ops_flag[16];
	char subname[40];
	char objname[1024];
	MAC_LABEL minsublevel;
	MAC_LABEL minobjlevel;	
	UINT16 Bret;
}FILTER;

static struct struct_elem_attr AUDIT_FILTER_desc[] =
{
	{"tm1",OS210_TYPE_TIME,sizeof(time_t),NULL},
	{"tm2",OS210_TYPE_TIME,sizeof(time_t),NULL},
	{"ops_flag",OS210_TYPE_BINDATA,16,NULL},
	{"subname",OS210_TYPE_STRING,40,NULL},
	{"objname",OS210_TYPE_STRING,1024,NULL},
	{"minsublabel",OS210_TYPE_ORGCHAIN,0,MAC_LABEL_desc},
	{"minobjlabel",OS210_TYPE_ORGCHAIN,0,MAC_LABEL_desc},
	{"Bret",OS210_TYPE_USHORT,sizeof(short),NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

typedef struct emu_auditinfo_list
{
	BYTE recordtype;  // the record type of this audit list,can be
			  // normal,key or except 
	Record_List recordlist; // a list which store the selected 
				   // audit record
	int recordnum;		   // store the record number in the audit list
	int currno;	   // the current audit record no in the
       				   //  audit record file 
	FILTER *auditfilter;       // an audit filter,it can filter the
                                   // audit record,remove the audit record which
				   // do not match the filter 
	struct list_head * currsite;   // the current list head
}AUDIT_LIST;

void * CreateAuditList()
{
	int retval;
	AUDIT_LIST * audit_list;
	audit_list=(AUDIT_LIST *)kmalloc(sizeof(AUDIT_LIST),GFP_KERNEL);
	if(audit_list==NULL)
		return -ENOMEM;
	memset(audit_list,0,sizeof(AUDIT_LIST));
	INIT_LIST_HEAD(&(audit_list->recordlist.list));
	audit_list->recordlist.record=NULL;
	audit_list->currsite=&(audit_list->recordlist.list);
	return audit_list;
}

int SetAuditListType(void * auditlist,int audittype)
{
	AUDIT_LIST * audit_list;
	audit_list=(AUDIT_LIST *)auditlist;
	if((audittype<=0 )|| (audittype>EXCEPT_AUDIT_RECORD))
		return -EINVAL;
	if((auditlist==NULL)|| IS_ERR(auditlist))
		return -EINVAL;
	audit_list->recordtype=audittype;
	return 0;
};

int GetAuditListType(void * auditlist)
{
	AUDIT_LIST * audit_list;
	audit_list=(AUDIT_LIST *)auditlist;
	if((auditlist==NULL)|| IS_ERR(auditlist))
		return -EINVAL;
	return audit_list->recordtype;
};


int SetAuditListFilter(void * auditlist,void * auditfilter)
{
	AUDIT_LIST * audit_list;
	audit_list=(AUDIT_LIST *)auditlist;
	if((auditlist==NULL)|| IS_ERR(auditlist))
		return -EINVAL;
	if((auditfilter==NULL)|| IS_ERR(auditfilter))
		return -EINVAL;
	audit_list->auditfilter=auditfilter;
	return 0;
};

void * GetAuditListFilter(void * auditlist)
{
	AUDIT_LIST * audit_list;
	audit_list=(AUDIT_LIST *)auditlist;
	if((auditlist==NULL)|| IS_ERR(auditlist))
		return -EINVAL;
	return audit_list->auditfilter;
};

int ReadAuditRecord(int fd,int recordnum,void * record)
{
	int retval;
	retval=lseek(fd,recordnum*sizeof(AUDIT_RECORD),SEEK_SET);
	if(retval<0)
	{
		printk("ReadAuditRecord find audit record error!\n");
		return retval;
	}
	retval=read(fd,record,sizeof(AUDIT_RECORD));
	if(retval!= sizeof(AUDIT_RECORD))
	{
		printk("ReadAuditRecord read audit record error!\n");
		return -EINVAL;
	}
	return 0;
}

int InsertAuditRecord(void * auditlist, void * auditrecord)
{
	AUDIT_LIST * audit_list;
	audit_list=(AUDIT_LIST *)auditlist;
	Record_List * tempelem;
	void * recordbuf;
	if((auditlist==NULL)|| IS_ERR(auditlist))
		return -EINVAL;
	if((auditrecord==NULL)|| IS_ERR(auditrecord))
		return -EINVAL;

	tempelem=(Record_List *)kmalloc(sizeof(Record_List),GFP_KERNEL);
	if(tempelem==NULL)
		return -ENOMEM;
	recordbuf=kmalloc(sizeof(AUDIT_RECORD),GFP_KERNEL);
	if(recordbuf==NULL)
	{
		kfree(tempelem);
		return -ENOMEM;
	}
	memcpy(recordbuf,auditrecord,sizeof(AUDIT_RECORD));
	tempelem->record=recordbuf;
	INIT_LIST_HEAD(&(tempelem->list));
	list_add_tail(&(tempelem->list),&(audit_list->recordlist.list));
	return 0;
}

int ReadAuditList(void * auditlist)
{
	AUDIT_LIST * audit_list;
	audit_list=(AUDIT_LIST *)auditlist;
	if((auditlist==NULL)|| IS_ERR(auditlist))
		return -EINVAL;

	int retval;
	Record_List * filelist;
	struct list_head * curr;
	Record_List * tempfile;

	int recordsize;
	BYTE * buffer;
	AUDIT_RECORD * recordbuf;
	char * filename;
	int fd;
	int recordoffset;   // record offset in the audit file
	int recordnum;      // how many record this list read
	AUDIT_RECORD * auditrecord;
// 	open the right audit file,fd is the handle of the audit file
	switch(audit_list->recordtype)
	{
		case NO_AUDIT_RECORD:
			return 0;
		case EXCEPT_AUDIT_RECORD:
			fd=open(EAUDIT_FILE,O_RDONLY);
			if(fd<0)
				return 0;
			break;
		case KEY_AUDIT_RECORD:
			fd=open(KAUDIT_FILE,O_RDONLY);
			if(fd<0)
				return 0;
			break;
		case NORMAL_AUDIT_RECORD:
			fd=open(AUDIT_FILE,O_RDONLY);
			if(fd<0)
				return 0;
			break;
		default:
			return 0;
	}

	// compute the audit record no.
	struct stat statbuf;
	if(fstat(fd,&statbuf)<0)

	{
		printf("fstat error\n");
		return -EIO;
	}

	recordsize = statbuf.st_size;
	recordoffset=recordsize/sizeof(AUDIT_RECORD);
	recordnum=0;
	retval=0;

	// read the audit record and insert it to the audit list
	
	#define BUF_RECORD_NUM  20
	recordbuf=(AUDIT_RECORD *)kmalloc(sizeof(AUDIT_RECORD)*BUF_RECORD_NUM,
		GFP_KERNEL);
	int bufcurrno=0;	
	  
	do
	{
		// begin to read the last record
		retval=ReadAuditRecord(fd,recordoffset-1,recordbuf+bufcurrno);
		recordoffset--;

		if((recordbuf[bufcurrno].iType>=KAUDIT_TYPE_EXPAND_SINGLE)
			&&(recordbuf[bufcurrno].iType<=KAUDIT_TYPE_EXPAND_TAIL))
		{
			bufcurrno++;
			if(bufcurrno>BUF_RECORD_NUM)
				return -E2BIG;
			continue;
		}
				
		auditrecord=recordbuf+bufcurrno;
		if(FilterRecord(auditrecord,audit_list->auditfilter)>0)
		{
			for(;bufcurrno>=0;bufcurrno--)
			{
				InsertAuditRecord(auditlist,
					recordbuf+bufcurrno);
				recordnum++;
			}
		}
		bufcurrno=0;
	}while((retval==0)&&(recordoffset>0));
	close(fd);
	audit_list->recordnum=recordnum;
	return recordnum;		
}

void * CreateAuditFilter()
{
	int retval;
	FILTER * audit_filter;
	audit_filter=(FILTER *)kmalloc(sizeof(FILTER),GFP_KERNEL);
	if(audit_filter==NULL)
		return -ENOMEM;
	memset(audit_filter,0,sizeof(FILTER));
	return audit_filter;
}

int SetAuditFilterAttr(void * filter,char * name, void * value)
{
	if(filter==NULL)
		return -EINVAL;
	if(name==NULL)
		return -EINVAL;
	if(value==NULL)
		return -EINVAL;
	return policy_struct_read_elem(name,filter,AUDIT_FILTER_desc,value);
}

void * GetAuditFilterAttr(void * filter,char * name)
{
	if(filter==NULL)
		return -EINVAL;
	if(name==NULL)
		return -EINVAL;
	return policy_struct_get_addr(name,filter,AUDIT_FILTER_desc);	
}

int SetAuditFilterOp(void * filter,int op, int on_off)
{
	if((op<0) || (op>=AUDIT_PROBE_END))
	{
		return -EINVAL;
	}	
	if(filter==NULL)
		return -EINVAL;

	BYTE * ops;
	ops=(BYTE *)GetAuditFilterAttr(filter,"ops_flag");
	int offset=(op-1)/8;
	BYTE Mask=1;
	Mask<<=(op-1)%8;
	if(on_off)
	{
		ops[offset] |= Mask;	
	}
	else
	{
		ops[offset] &= (~Mask);	
	}
	return 0;
}

int FilterRecord(void * auditrecord,void * auditfilter)
{
	AUDIT_RECORD * record;
	record=(AUDIT_RECORD *)auditrecord;
	FILTER * filter;
	filter=(FILTER *)auditfilter;
	if((record==NULL)|| IS_ERR(record))
		return -EINVAL;
	// if filter is null,all the record will pass the filter
	if(filter==NULL)
		return 1;
	if(IS_ERR(filter))
		return -EINVAL;
	// time filter
	if((filter->tm1 != 0) &&(filter->tm1 > record->Time))
		return 0;
	if((filter->tm2 != 0) &&(filter->tm2 < record->Time))
		return 0;

	// operation filter
	if((record->NodeID<0) ||(record->NodeID>256))
		return -EINVAL;
	int offset=(record->NodeID-1)/8;
	BYTE ProbeMask=1;
	ProbeMask<<=(record->NodeID-1)%8;
	if(!(ProbeMask & filter->ops_flag[offset]))
		return 0;
	//subname filter
	//objname filter
	
	//minsublevel filter
	//minobjlevel filter
	
	//retvalue filter
		if(!(record->Bret & filter->Bret))
			return 0;
	return 1;	
}
time_t ConvertTimeString(char * string)
{
			
	struct tm * tm_time;
	time_t t_time;
	
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
	tm_time->tm_mon=atoi(buf)-1;
	//convert day
	memcpy(buf,string+6,2);
	buf[2]=0;
	tm_time->tm_mday=atoi(buf)-1;
	//convert hour
	memcpy(buf,string+8,2);
	buf[2]=0;
	tm_time->tm_hour=atoi(buf)-1;
	//convert minute
	memcpy(buf,string+10,2);
	buf[2]=0;
	tm_time->tm_min=atoi(buf)-1;
	//convert second
	memcpy(buf,string+12,2);
	buf[2]=0;
	tm_time->tm_sec=atoi(buf)-1;
	t_time=mktime(tm_time);
	free(tm_time);
	return t_time;
}

int IsAnExpandAuditRecord(void * record)
{
	AUDIT_RECORD * auditrecord;
	auditrecord = (AUDIT_RECORD *)record;
	if((auditrecord->iType>=KAUDIT_TYPE_EXPAND_SINGLE)
		&&(auditrecord->iType<=KAUDIT_TYPE_EXPAND_TAIL))
		return auditrecord->iType;
	return 0;
}

int GetLastAuditRecord(void * record,void * AuditList)
{
	Record_List * record_elem;
	AUDIT_LIST * auditlist;
	auditlist=(AUDIT_LIST *)AuditList;
	struct list_head * head, *curr;
	AUDIT_RECORD * temprecord;

	head=&(auditlist->recordlist.list);

	curr=head->next;
	while(curr!=head)
	{
		record_elem=list_entry(curr,Record_List,list);
		temprecord=(AUDIT_RECORD *)record_elem->record;
		if(IsAnExpandAuditRecord(temprecord))
		{
			curr=curr->next;
			continue;
		}
		memcpy(record,record_elem->record,sizeof(AUDIT_RECORD));
		auditlist->currsite=curr;
		return 1;
	}
	return 0;
}

int GetPrevAuditRecord(void * record,void * AuditList)
{
	Record_List * record_elem;
	AUDIT_LIST * auditlist;
	auditlist=(AUDIT_LIST *)AuditList;
	struct list_head * head, *curr;
	AUDIT_RECORD * temprecord;

	head=&(auditlist->recordlist.list);

	curr=auditlist->currsite->next;
	while(curr!=head)
	{
		record_elem=list_entry(curr,Record_List,list);
		temprecord=(AUDIT_RECORD *)record_elem->record;
		if(IsAnExpandAuditRecord(temprecord))
		{
			curr=curr->next;
			continue;
		}
		memcpy(record,record_elem->record,sizeof(AUDIT_RECORD));
		auditlist->currsite=curr;
		return 1;
	}
	return 0;
}

const void * GetCurrRecordSite(void * AuditList)
{
	AUDIT_LIST * auditlist;
	auditlist=(AUDIT_LIST *)AuditList;
	return auditlist->currsite;
}

int SetCurrRecordSite(void * currsite,void * auditlist)
{
	AUDIT_LIST * audit_list;
	audit_list=(AUDIT_LIST *)auditlist;
	audit_list->currsite=currsite;
	return 1;
}

#define EXPANDDATALEN  60
#define RECORDNAMELEN  18
#define MAXEXPANDNUM   30

void * GetExpandName(void * auditlist,char * name,int namelen)
{
	AUDIT_LIST * audit_list;
	Record_List * record_elem;
	audit_list=(AUDIT_LIST *)auditlist;
	struct list_head * head, *curr;
	AUDIT_EXPANDRECORD * expandbag;
	int retval;
	int start=0;
	int offset=0;
	int left=namelen;

	head=&(audit_list->recordlist.list);
	curr=(struct list_head *)(audit_list->currsite);
	while(curr->next!=head)
	{
		curr=curr->next;
		record_elem=list_entry(curr,Record_List,list);
		expandbag=(AUDIT_EXPANDRECORD *)(record_elem->record);
		if(!IsAnExpandAuditRecord(expandbag))
		{
			printk("read expand bag err!\n!");
			return expandbag->iType;
		}
		switch(expandbag->iType){
			case KAUDIT_TYPE_EXPAND_SINGLE:
			case KAUDIT_TYPE_EXPAND_HEAD:
				if(start!=0)
					return -EINVAL;
				if(namelen<=RECORDNAMELEN+EXPANDDATALEN)
				{
					offset=namelen-RECORDNAMELEN;
					left=0;
				}
				else
				{
					offset=60;
					left=namelen-60;
				}
				memcpy(name,expandbag->ExpandData,offset);
				start=start+offset;
				break;

			case KAUDIT_TYPE_EXPAND:
				if(left<=RECORDNAMELEN+EXPANDDATALEN)
				{
					offset=left;
					left=0;
				}
				else
				{
					offset=60;
					left-=60;
				}
				memcpy(name+start,expandbag->ExpandData,
					offset);
				start+=offset;
				break;
			case KAUDIT_TYPE_EXPAND_TAIL:
				if(left>RECORDNAMELEN+EXPANDDATALEN)
				{
					printk("read expand bag err!\n!");
					return -EINVAL;
				}
				offset=left-RECORDNAMELEN;
				left=RECORDNAMELEN;
				memcpy(name+start,expandbag->ExpandData,
					offset);
			default:
				break;
		}
		if((expandbag->iType==KAUDIT_TYPE_EXPAND_SINGLE)
			||(expandbag->iType==KAUDIT_TYPE_EXPAND_TAIL))
			break;
	}while(left>0);	
	return curr;
}

int printnamedvalue(int value,void * namelist)
{
	NAME2VALUE  * list;
	list=(NAME2VALUE *)namelist;
	int i=0;
	while(list[i].name!=NULL)
	{
		if(list[i].value==value){
			printf("%s\t",list[i].name);
			break;
		}
		i++;
	}
	if(list[i].name==NULL)
	{
		printf("errvalue\t");
		return -EINVAL;
	}
	return 0;
}

int OutputAuditRecord(void * record)
{

	AUDIT_RECORD * auditrecord;
	auditrecord=(AUDIT_RECORD *)record;
	struct __attribute((packed))__ 
	{
		UINT16  pid;
		UINT16  superno;
		UINT32	ino;
	} Reserved;
	int tempvalue;
	int i;

//      print the ProbeNo
	printf("ProbeNo: ");
	printnamedvalue(auditrecord->NodeID,Audit_Probe_name);

//	print the iType
	tempvalue=auditrecord->iType&0xFF;
	printnamedvalue(tempvalue,Audit_OpType_name);

//	print the time
	struct tm * tm_time;
       	tm_time	= localtime(&(auditrecord->Time));
	if(tm_time != NULL)
	{
		printf("Time: %4d.%2d.%2d %2d:%2d:%2d ",
			tm_time->tm_year+1900,
			tm_time->tm_mon+1,tm_time->tm_mday,
			tm_time->tm_hour,tm_time->tm_min,
			tm_time->tm_sec);
	}
	else
	{
		printk("Time: %d ",auditrecord->Time);	
	}

	char namebuf[20];
	int namelen;
	printf("\n");
//	print subname and sublabel
		
	namelen=*(short *)auditrecord->SubName;
	if((namelen>=128) || (namelen<0))
	{
		printf("Sub Name: errvalue! ");
	}
	else
	{
		printf("Sub Name:  ");
		if(namelen>18)
		{
			printf("*");
			namelen=18;
		}
		memcpy(namebuf,auditrecord->SubName+2,namelen);
		namebuf[namelen]=0;
		printf("%s  ",namebuf);
	}

	printf("Label: %d %d",			
		auditrecord->SubLabel.ConfLevel,
		auditrecord->SubLabel.InteLevel);
	printf(" ");
	for(i=0;i<8;i++)
	{
		printf("%2.2x ",auditrecord->SubLabel.SecClass[i]);
	}
// print subtype
	printf("Type: %2.2x",auditrecord->SubType);
		
	printf("\n");
//	print objname and objlabel
		
		
	namelen=*(short *)auditrecord->ObjName;
	if((namelen>=1024) || (namelen<0))
	{
		printf("Obj Name: errvalue! ");
	}
	else
	{
		printf("Obj Name:  ");
		if(namelen>18)
		{
			printf("*");
			namelen=18;
		}
		if(namelen>18)
			namelen=18;
		memcpy(namebuf,auditrecord->ObjName+2,namelen);
		namebuf[namelen]=0;
		printf("%s  ",namebuf);
	}

		auditrecord->SubLabel.ConfLevel,
	printf("Label: %d %d",			
		auditrecord->ObjLabel.ConfLevel,
		auditrecord->ObjLabel.InteLevel);
	printf(" ");
	for(i=0;i<8;i++)
	{
		printf("%2.2x ",auditrecord->ObjLabel.SecClass[i]);
	}
// print objtype
	printf("Type: %2.2x",auditrecord->ObjType);

//	print Bret 
	printf("\n Bret: ");
	tempvalue=auditrecord->Bret%256;
	printnamedvalue(tempvalue,Audit_Retvalue_name);	
// 	print Reserved value
	memcpy(&Reserved,auditrecord->Reserved,sizeof(Reserved));
	printk("Reserved: pid= %d ino = %d \n",
		Reserved.pid,Reserved.ino);	
}

int IfAuditRecordHasExpand(void * record)
{
	AUDIT_RECORD * auditrecord;
	auditrecord = (AUDIT_RECORD *)record;
	return auditrecord->iType/256;
}

int OutputAuditRecordWithExpand(void * record,void * curr,void * auditlist)
{
	AUDIT_RECORD * auditrecord;
	auditrecord=(AUDIT_RECORD *)record;
	void * currsite;
	struct __attribute((packed))__ 
	{
		UINT16  pid;
		UINT16  superno;
		UINT32	ino;
	} Reserved;
	int tempvalue;
	int i;
	AUDIT_RECORD * expandrecord;
	char expandname[1024];

//      print the ProbeNo
	printf("ProbeNo: ");
	printnamedvalue(auditrecord->NodeID,Audit_Probe_name);

//	print the iType
	tempvalue=auditrecord->iType&0xFF;
	printnamedvalue(tempvalue,Audit_OpType_name);

//	print the time
	struct tm * tm_time;
       	tm_time	= localtime(&(auditrecord->Time));
	if(tm_time != NULL)
	{
		printf("Time: %4d.%2d.%2d %2d:%2d:%2d ",
			tm_time->tm_year+1900,
			tm_time->tm_mon+1,tm_time->tm_mday,
			tm_time->tm_hour,tm_time->tm_min,
			tm_time->tm_sec);
	}
	else
	{
		printk("Time: %d ",auditrecord->Time);	
	}

	char namebuf[1024];
	int namelen;
	printf("\n");

	currsite=curr;
//	print subname and sublabel
		
	namelen=*(short *)auditrecord->SubName;
	if((namelen>=128) || (namelen<0))
	{
		printf("Sub Name: errvalue! ");
	}
	else
	{
		printf("Sub Name:  ");
		if(namelen>RECORDNAMELEN)
		{
			currsite=GetExpandName(auditlist,namebuf,namelen);
			memcpy(namebuf+namelen-RECORDNAMELEN,
				auditrecord->SubName+2,RECORDNAMELEN);
		}
		else
		{
			memcpy(namebuf,auditrecord->SubName+2,namelen);
		}
		namebuf[namelen]=0;
		printf("%s  ",namebuf);
		
	}

	printf("Label: %d %d",			
		auditrecord->SubLabel.ConfLevel,
		auditrecord->SubLabel.InteLevel);
	printf(" ");
	for(i=0;i<8;i++)
	{
		printf("%2.2x ",auditrecord->SubLabel.SecClass[i]);
	}
// print subtype
	printf("Type: %2.2x",auditrecord->SubType);
		
	printf("\n");
//	print objname and objlabel
		
		
	namelen=*(short *)auditrecord->ObjName;
	if((namelen>=1024) || (namelen<0))
	{
		printf("Obj Name: errvalue! ");
	}
	else
	{
		printf("Obj Name:  ");
		if(namelen>18)
		{
			currsite=GetExpandName(auditlist,namebuf,namelen);
			memcpy(namebuf+namelen-RECORDNAMELEN,
				auditrecord->SubName+2,RECORDNAMELEN);
		}
		else {
			memcpy(namebuf,auditrecord->ObjName+2,namelen);
		}
		namebuf[namelen]=0;
		printf("%s  ",namebuf);
	}

		auditrecord->SubLabel.ConfLevel,
	printf("Label: %d %d",			
		auditrecord->ObjLabel.ConfLevel,
		auditrecord->ObjLabel.InteLevel);
	printf(" ");
	for(i=0;i<8;i++)
	{
		printf("%2.2x ",auditrecord->ObjLabel.SecClass[i]);
	}
// print objtype
	printf("Type: %2.2x",auditrecord->ObjType);
	
//	print Bret 
	printf("\n Bret: ");
	tempvalue=auditrecord->Bret%256;
	printnamedvalue(tempvalue,Audit_Retvalue_name);	
// 	print Reserved value
	memcpy(&Reserved,auditrecord->Reserved,sizeof(Reserved));
	printk("Reserved: pid= %d ino = %d \n\n",
		Reserved.pid,Reserved.ino);	

}

int  DelAuditFilter(void * AuditFilter)
{

}
int  DelAuditList(void * AuditList)
{

}
