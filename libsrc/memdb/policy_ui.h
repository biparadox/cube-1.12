#ifndef _OS210_VERIFY_POLICYUI_H
#define _OS210_VERIFY_POLICYUI_H

#include <time.h>
//#include "../../include/extern_interface.h"


//#define MAX_RECORD_NUM 200000

// 节点信息数据结构
//
//


/*
struct tagElemList
{
	Record_List list;
	const struct struct_elem_attr * struct_desc;
	struct list_head curr;
}ELEM_LIST;
*/
// Audit File Select Function

// Interface with the Manage Module
int SelectAuditInfo(time_t tm1,time_t tm2, int oper_type,char * keyword);

int MakePackage(char * head_info,BYTE * string,void * Package_Data, int string_size);

// Policy Functionse
int InitPolicyLib();

int LoadPolicy(char * policytype);

void * FindPolicy(void * tag, char * policytype);

void * TypeFindPolicy(int findtype,void * tag, char * policytype);

void * GetFirstPolicy(char * policytype);

void * GetNextPolicy(char * policytype);

void * BuildPolicy(char * policystring,char * policytype); 
char * OutputPolicy(void * policy,char * policytype,int size); 

int AddPolicy(void * policy,char * policytype);

int ModifyPolicy(void * policy,char * name,void * value,char * policytype);

int DelPolicy(void * policyname,char * policytype);

int LoadTxtPolicyFile(char * filename,char * type,BYTE ** buf);

int LoadPolicyData(BYTE * PolicyPackage);

int ExportPolicyPackage(void ** policy,char * policytype,int size);

int ExportPolicyToFile(char * filename,char * policytype);

int UpdatePolicyFile(char * policytype);


// Audit Function:
void * CreateAuditFilter();

int SetAuditFilterAttr(void * filter,char * name, void * value);
void * GetAuditFilterAttr(void * filter,char * name);

int SetAuditFilterOp(void * filter,int op, int on_off);

int SetAuditReturnMask(int mask,void * AuditFilter);

int GetLastAuditRecord(void * record,void * AuditList);

int GetPrevAuditRecord(void * record,void * AuditList);

const void * GetCurrRecordSite(void * AuditList);

int SetCurrRecordSite(void * currsite,void * auditlist);

int OutputAuditRecord(void * record);

int IfAuditRecordHasExpand(void * record);
//int IsExpandAuditRecord(void * record);

void * GetExpandName(void * currsite,char * name,int length);

int OutputAuditRecordWithExpand(void * record,void * curr,void * auditlist);

int  DelAuditFilter(void * AuditFilter);
int  DelAuditList(void * AuditList);
time_t ConvertTimeString(char * string);

// tool function
#endif
