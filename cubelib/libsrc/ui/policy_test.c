#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "../include/data_type.h"
#include "../include/struct_deal.h"
#include "../include/extern_struct.h"
#include "../include/extern_struct_desc.h"
#include "../include/logic_baselib.h"
#include "../include/extern_defno.h"
#include "policy_ui.h"

const char * fixed_policy_dir = "/etc/policy/local/";
const char * conf_policy_dir = "/etc/policy/user/";
#define MAX_NAME_LEN 512 
/*
typedef struct tagMAC_Label   //Ç¿ÖÆ·ÃÎÊ¿ØÖÆ±ê¼Ç
{
   BYTE ConfLevel;         	//±£ÃÜ¼¶±ð 
   BYTE InteLevel;         //ÍêÕû¼¶±ð
   BYTE SecClass[8];        //Ö÷/¿ÍÌå·¶³ë
} __attribute__((packed)) MAC_LABEL;
typedef struct tagAudit_Record
{
   UINT16 NodeID;  	     	//½ÚµãÐòÁÐºÅ
   UINT16 iType;       	 	//Éó¼ÆÀàÐÍ
   UINT32 Time;  	  	//Éó¼ÆÊÂ¼þ·¢ÉúÊ±¼ä
   BYTE SubName[20];           //Ö÷ÌåÃû³Æ
   MAC_LABEL SubLabel;	
   BYTE SubType;	
   BYTE ObjName[20];           //¿ÍÌåÃû³Æ    
   MAC_LABEL ObjLabel;	
   BYTE ObjType;
   UINT16 Bret;       	 	  //Éó¼ÆÀàÐÍ
   BYTE Reserved[8];  		//±£Áô×Ö¶Î
} __attribute__((packed)) AUDIT_RECORD;  

//À©Õ¹Éó¼ÆÊý¾Ý½á¹¹
typedef struct tagKAudit_Record            //wdh 20110601
{
	 UINT16 NodeID;         //½Úµã±àºÅ
	 UINT16 iType;          //Éó¼ÆÀàÐÍ
	 UINT16 ExpandNo;       //À©Õ¹°üÐòºÅ
	 BYTE ExpandData[60];  //À©Õ¹Êý¾Ý
	 BYTE Reserved1[6];     //±£Áô×Ö¶Î
	 BYTE Reserved[8];     //±£Áô×Ö¶Î
}__attribute__((packed)) AUDIT_EXPANDRECORD;  
*/
/*
typedef struct tagnameofvalue
{
	char * name;
	int value;
}NAME2VALUE;
*/

int main(int argc,char *argv[])
{
	int i,j,num;
	
	int retval;
	int recordsize,certsize;
	
	int templen;
	void *p;
	unsigned char *temp;
	struct stat statbuf;
	BYTE * buffer, *databuffer;
	int fd;

	retval=0;

	// test the policy function
	InitPolicyLib();

	LoadTxtPolicyFile("../txtpolicy/sublist.txt","SUBL",&buffer);
	LoadPolicyData(buffer);
	free(buffer);

	char * newPolicyString="/etc/rc2.d/s02syslog	syslog	0	16	AAAAAAAAAAA	20 	AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	void * policy;
	policy=BuildPolicy(newPolicyString,"SUBL");
	if(policy==NULL)
	{
		printf("Build Policy Struct Error!");
		return 0;
	}
	OutPutPolicy(policy,"SUBL");
	printf("\n");
	AddPolicy(policy,"SUBL");
	char * newPolicyString1="/etc/rc2.d/s02syslog	device	0	12	AAAAAAAAAAA	0";
	policy=BuildPolicy(newPolicyString1,"SUBL");
	if(policy==NULL)
	{
		printf("Build Policy Struct Error!");
		return 0;
	}
	AddPolicy(policy,"SUBL");

	policy=FindPolicy("$auditd","SUBL");

	UpdatePolicyFile("SUBL");

	LoadPolicy("SUBL");

	policy=GetFirstPolicy("SUBL");
	i=0;
	while(policy!=NULL)
	{
		OutPutPolicy(policy,"SUBL");
		printf("\n");
		policy=GetNextPolicy("SUBL");
		i++;
	}	

	//  update OBJL policy
	LoadTxtPolicyFile("../txtpolicy/objlist.txt","OBJL",&buffer);
	LoadPolicyData(buffer);
	free(buffer);
	policy=GetFirstPolicy("OBJL");
	i=0;
	while(policy!=NULL)
	{
		OutPutPolicy(policy,"OBJL");
		printf("\n");
		policy=GetNextPolicy("OBJL");
		i++;
	}	
	UpdatePolicyFile("OBJL");

	//  update AUUL policy
	LoadTxtPolicyFile("../txtpolicy/uidfile.txt","AUUL",&buffer);
	LoadPolicyData(buffer);
	free(buffer);
	policy=GetFirstPolicy("AUUL");
	i=0;
	while(policy!=NULL)
	{
		OutPutPolicy(policy,"AUUL");
		printf("\n");
		policy=GetNextPolicy("AUUL");
		i++;
	}	
	UpdatePolicyFile("AUUL");

	// update AUDI policy
	LoadTxtPolicyFile("../txtpolicy/auditlist.txt","AUDI",&buffer);
	LoadPolicyData(buffer);
	free(buffer);
	policy=GetFirstPolicy("AUDI");
	i=0;
	while(policy!=NULL)
	{
		OutPutPolicy(policy,"AUDI");
		printf("\n");
		policy=GetNextPolicy("AUDI");
		i++;
	}	
	UpdatePolicyFile("AUDI");

	// test the policy function
/*	
	void * filter1, *filter2;
	void * auditlist;

	filter1=CreateAuditFilter();
	filter2=CreateAuditFilter();
	
	time_t time;
	time=ConvertTimeString("20111117120000");

	SetAuditFilterAttr(filter1,"tm1",&time);
	unsigned short Bret=0xff;
	SetAuditFilterAttr(filter1,"Bret",&Bret);

	auditlist=CreateAuditList();

	SetAuditFilterOp(filter1,AUDIT_PROBE_EXEC_FILE,1);
	SetAuditListFilter(auditlist,filter1);
	SetAuditListType(auditlist,KEY_AUDIT_RECORD);
	retval=ReadAuditList(auditlist);
	printf("read %d audit record!\n",retval);
		
	AUDIT_RECORD audit_record;	
	retval=GetLastAuditRecord(&audit_record,auditlist);
	while(retval>0)
	{
		if(IfAuditRecordHasExpand(&audit_record))
		{
			void * currsite;
			currsite=GetCurrRecordSite(auditlist);
			OutputAuditRecordWithExpand(&audit_record,
				currsite,auditlist);
		}
		else
		{
			OutputAuditRecord(&audit_record);

		}	
		retval=GetPrevAuditRecord(&audit_record,auditlist);
	}
	

	DelAuditList(auditlist);
	DelAuditFilter(filter1);
	DelAuditFilter(filter2);
	*/
	return 0;
}
