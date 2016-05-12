/*************************************************
*       project:        973 trust demo, zhongan secure os 
*                       and trust standard verify
*	name:		extern_struct_desc.h
*	write date:    	2011-08-04
*	auther:    	Hu jun
*       content:        this file describe the extern struct's format with
*       		attr struct array
*       changelog:       
*************************************************/
#ifndef _OS210_EXTERN_STRUCT_DESC_H
#define _OS210_EXTERN_STRUCT_DESC_H

#include "data_type.h"
#include "struct_deal.h"

static struct struct_elem_attr MAC_LABEL_desc[] =
{
	{"ConfLevel",OS210_TYPE_UCHAR,1,NULL},
	{"InteLevel",OS210_TYPE_UCHAR,1,NULL},
	{"SecClass",OS210_TYPE_BINDATA,8,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
/*
static struct struct_elem_attr TRUST_LABEL_desc[] =
{
	{"DomainType",OS210_TYPE_UCHAR,1,NULL},
	{"DomainNo",OS210_TYPE_INT,1,NULL},
	{"Flag",OS210_TYPE_UCHAR,1,NULL},
	{"State",OS210_TYPE_USHORT,2,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};*/

static struct struct_elem_attr AuthUser_desc[] =
{
	{"UserName",OS210_TYPE_VSTRING,40,NULL},
	{"UserID",OS210_TYPE_INT,16,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL},
};

static struct struct_elem_attr TrustFile_desc[] =
{
	{"FileName",OS210_TYPE_VSTRING,1024,NULL},
	{"Digest",OS210_TYPE_INT,sizeof(int),NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr SUB_LABEL_desc[] =
{
	{"SubName",OS210_TYPE_VSTRING,40,NULL},
	{"GroupName",OS210_TYPE_VSTRING,1024,NULL},
	{"MacLabel",OS210_TYPE_ORGCHAIN,0,MAC_LABEL_desc},
//	{"TrustLabel",OS210_TYPE_ORGCHAIN,0,TRUST_LABEL_desc},
	{"SubType",OS210_TYPE_UCHAR,1,NULL},
	{"SubID",OS210_TYPE_USHORT,2,NULL},
	{"KeyPart",OS210_TYPE_BINDATA,32,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr OBJ_LABEL_desc[] =
{
	{"ObjName",OS210_TYPE_VSTRING,1024,NULL},
	{"MacLabel",OS210_TYPE_ORGCHAIN,0,MAC_LABEL_desc},
//	{"TrustLabel",OS210_TYPE_ORGCHAIN,0,TRUST_LABEL_desc},
	{"ObjType",OS210_TYPE_UCHAR,1,NULL},
	{"MntID",OS210_TYPE_USHORT,2,NULL},
	{"ObjID",OS210_TYPE_INT,4,NULL},
	{"KeyPart",OS210_TYPE_BINDATA,32,NULL},
	{"Digest",OS210_TYPE_BINDATA,32,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr DAC_desc[] =
{
	{"SubName",OS210_TYPE_VSTRING,40,NULL},
	{"ObjName",OS210_TYPE_VSTRING,1024,NULL},
	{"OpType",OS210_TYPE_UCHAR,1,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr PRIV_desc[] =
{
	{"SubName",OS210_TYPE_VSTRING,40,NULL},
	{"ObjName",OS210_TYPE_VSTRING,1024,NULL},
	{"OpType",OS210_TYPE_UCHAR,1,NULL},
	{"AuthOwnerName",OS210_TYPE_VSTRING,40,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr AUDIT_POLICY_desc[] =
{
	{"NodeID",OS210_TYPE_USHORT,sizeof(short),NULL},
	{"Type",OS210_TYPE_USHORT,sizeof(short),NULL},
	{"Bret",OS210_TYPE_HEXDATA,sizeof(short),NULL},
	{"On_Off",OS210_TYPE_HEXDATA,sizeof(int),NULL},
	{"NotBeforeTime",OS210_TYPE_STRING,16,NULL},
	{"NotAfterTime",OS210_TYPE_STRING,16,NULL},
	{"Reserved",OS210_TYPE_BINDATA,4,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
static struct struct_elem_attr AUDIT_RECORD_desc[] =
{
	{"NodeID",OS210_TYPE_USHORT,sizeof(short),NULL},
	{"Type",OS210_TYPE_USHORT,sizeof(short),NULL},
	{"Time",OS210_TYPE_TIME,sizeof(int),NULL},
	{"SubName",OS210_TYPE_STRING,2,NULL},
	{"SubLabel",OS210_TYPE_ORGCHAIN,0,MAC_LABEL_desc},
	{"SubType",OS210_TYPE_UCHAR,1,NULL},
	{"ObjName",OS210_TYPE_STRING,2,NULL},
	{"ObjLabel",OS210_TYPE_ORGCHAIN,0,MAC_LABEL_desc},
	{"ObjType",OS210_TYPE_UCHAR,1,NULL},
	{"Bret",OS210_TYPE_HEXDATA,2,NULL},
	{"Reserved",OS210_TYPE_BINDATA,8,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
static struct struct_elem_attr AUDIT_EXPAND_RECORD_desc[] =
{
	{"NodeID",OS210_TYPE_USHORT,sizeof(short),NULL},
	{"Type",OS210_TYPE_USHORT,sizeof(short),NULL},
	{"ExpandNo",OS210_TYPE_USHORT,sizeof(short),NULL},
	{"ExpandData",OS210_TYPE_BINDATA,60,NULL},
	{"Reserved1",OS210_TYPE_BINDATA,6,NULL},
	{"Reserved",OS210_TYPE_BINDATA,8,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
static struct struct_elem_attr PROTOCOL_HEAD_desc[] =
{
	{"Protocol",OS210_TYPE_STRING,sizeof(UINT32),NULL},
	{"Version",OS210_TYPE_INT,sizeof(UINT32),NULL},
	{"Type",OS210_TYPE_STRING,sizeof(UINT32),NULL},
	{"Flags",OS210_TYPE_BITMAP,sizeof(UINT32),NULL},
	{"DataLength",OS210_TYPE_INT,sizeof(UINT32),NULL},
	{"eType",OS210_TYPE_INT,sizeof(UINT32),NULL},
	{"ExpandLength",OS210_TYPE_INT,sizeof(UINT32),NULL},
	{"Reserved",OS210_TYPE_INT,sizeof(UINT32),NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr Policy_Protocol_desc[] =
{
	{"Head",OS210_TYPE_ORGCHAIN,0,PROTOCOL_HEAD_desc},
	{"Data",OS210_TYPE_DEFINE,sizeof(BYTE),"Head.DataLength"},
	{"eData",OS210_TYPE_DEFINE,sizeof(BYTE),"Head.ExpandLength"},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr POLICY_HEAD_desc[] =
{
	{"NodeSequence",OS210_TYPE_BINDATA,20,NULL},
	{"UserName",OS210_TYPE_STRING,40,NULL},
	{"PolicyType",OS210_TYPE_BINDATA,4,NULL},
	{"PolicyVersion",OS210_TYPE_BINDATA,8,NULL},
	{"RecordNum",OS210_TYPE_INT,sizeof(UINT32),NULL},
	{"Reserved",OS210_TYPE_BINDATA,4,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
static struct struct_elem_attr MESSAGE_HEAD_desc[] =
{
	{"NodeSequence",OS210_TYPE_BINDATA,20,NULL},
	{"UserName",OS210_TYPE_STRING,40,NULL},
	{"PolicyType",OS210_TYPE_BINDATA,4,NULL},
	{"PolicyVersion",OS210_TYPE_BINDATA,8,NULL},
	{"MessageType",OS210_TYPE_BINDATA,4,NULL},
	{"DataLength",OS210_TYPE_INT,sizeof(int),NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
#endif
