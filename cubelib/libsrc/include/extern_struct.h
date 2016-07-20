/*************************************************
*       project:        973 trust demo, zhongan secure os 
*                       and trust standard verify
*	name:		extern_struct.h
*	write date:    	2011-08-04
*	auther:    	Hu jun
*       content:        this file describe the module's extern struct 
*       changelog:       
*************************************************/
#ifndef _OS210_EXTERN_STRUCT_H
#define _OS210_EXTERN_STRUCT_H
//#include "data_type.h"
typedef struct tagMAC_Label   //ǿ�Ʒ��ʿ��Ʊ��
{
   BYTE ConfLevel;         	//���ܼ��� 
   BYTE InteLevel;         //��������
   BYTE SecClass[8];        //��/���巶��
} __attribute__((packed)) MAC_LABEL;

typedef struct tagTrust_Label   //ǿ�Ʒ��ʿ��Ʊ��
{
   BYTE DomainType;         //���ܼ��� 
   int DomainNo;           //��������
   BYTE Flag;        //��/���巶��
   UINT16 State;
} __attribute__((packed)) TRUST_LABEL;

// subject label 
typedef struct tagSubjectLabel
{
   V_String SubName;   	  //subject name
   V_String GroupName;    //subject's group name 
   MAC_LABEL MacLabel;    //subject's secure label
// TRUST_LABEL TrustLabel;  // subject's trust label
   BYTE SubType;	    //subject type
   WORD SubID;		    //subject's unique id in local system	
   BYTE Keypart[32];        //subject key part 
} __attribute__((packed)) SUB_LABEL;  

// object label 
typedef struct tagObjectLabel
{
   V_String ObjName;   	  //object name
   MAC_LABEL MacLabel;    //object's secure label
// TRUST_LABEL TrustLabel;  // object's trust label
   BYTE ObjType;	    //object type
   WORD MntID;		    //the Mount file system's unique id
   DWORD ObjID;		    //the Object's unique id 	
   BYTE Digest[32];         //object data's digest
   BYTE KeyPart[32];        //object key part
} __attribute__((packed)) OBJ_LABEL;  

// protocol head struct 
typedef struct tagProtocolHead 
{
  	 UINT32 Protocol;       //Э��ͷ
  	 UINT32 Version;        //�汾�� 
  	 UINT32 Type;           //�ӿ�����
  	 UINT32 Flags;          //Э���־λ
	 UINT32 DataLength;   //???��??3��?��
	 UINT32 eType;
  	 UINT32 ExpandLength;   //�������
  	 UINT32 Reserved;    //����
} __attribute__((packed)) PROTOCOL_HEAD;


typedef struct tagPolicyProtocol
{
   PROTOCOL_HEAD Head;	
   BYTE * Data;           //��������   
   BYTE * eData;          //����������
} __attribute__((packed)) POLICY_PROTOCOL;  

//�����������ݰ����ݶ���
typedef struct tagPolicyRequestPackage
{
    BYTE NodeSequence[20];     //�ڵ����к�
    BYTE UserName[40];         //�û���
    UINT32 ExtendDataLength;   //��չ��Ϣ����
    BYTE * ExtendData;         //��չ��Ϣ���� 
} __attribute__((packed)) POLICY_REQ_PACK; 

#define OPERATE_TYPE_EXEC     0x10
#define OPERATE_TYPE_RENAME   0x08
#define OPERATE_TYPE_DELETE   0x04
#define OPERATE_TYPE_WRITE    0x02
#define OPERATE_TYPE_READ     0x01

#define OBJECT_TYPE_SYSFILE   	0x10
#define OBJECT_TYPE_AUDITFILE 	0x08
#define OBJECT_TYPE_POLICYFILE 	0x04
#define OBJECT_TYPE_WORKFILE 	0x02
#define OBJECT_TYPE_CRYPT	0x01

// ϵͳ�������ʿ��Ʋ��Խṹ
typedef struct tagDACPolicy
{
   V_String SubName;        //��������
   V_String ObjName;        //��������
   BYTE OpType;       //��������
   BYTE ObjType;           //��������   
} __attribute__((packed)) DAC_POLICY;  

// ϵͳ����������Խṹ
typedef struct tagPrivPolicy
{
   V_String SubName;         		//��������
   V_String ObjName;         		//��������
   BYTE OpType;      		//��������
   V_String AuthOwnerName;    //��Ȩ������
} __attribute__((packed)) PRIV_POLICY;  

typedef struct tagUserIDPolicy
{
   V_String SubName;         	//��������
   int userid;         		//��������
} __attribute__((packed)) USERID_POLICY;  

typedef struct auditpolicytime
{
    BYTE Year[4];
    BYTE Month[2];
    BYTE Day[2];
    BYTE Hour[2];
    BYTE Min[2];
    BYTE Second[2];
    BYTE Week[2];
}APTIME;

// ��Ʋ������ݽṹ
typedef struct tagAuditPolicy
{
   UINT16 NodeID;  	 	 //�ڵ����к�
   UINT16 iType;       	 	 //�������
   UINT16 Bret;       	 	 //��Ʋ���
   UINT32 On_Off;		 //Mask of audit policy,the lowest 8 bit is
  			         // the mask of except audit,the 8-15bit is 
				 // the mask of key audit, the 16-23bit is
				 // the mask of normal audit, the 24-31bit
				 // is the mask of total inforation audit 
   char BeginTime[16];  	  	 //���̽ͷ����ʱ��
   char EndTime[16];		 //���̽ͷ�ر�ʱ��	
   UINT32 Reserved;  		 //�����ֶ�
} __attribute__((packed)) AUDIT_POLICY;  



// ��Ʋ������ݽṹ
typedef struct tagAudit_Record
{
   UINT16 NodeID;  	     	//�ڵ����к�
   UINT16 iType;       	 	//�������
   UINT32 Time;  	  	//����¼�����ʱ��
   BYTE SubName[20];           //��������
   MAC_LABEL SubLabel;	
   BYTE SubType;	
   BYTE ObjName[20];           //��������    
   MAC_LABEL ObjLabel;	
   BYTE ObjType;
   UINT16 Bret;       	 	  //�������
   BYTE Reserved[8];  		//�����ֶ�
} __attribute__((packed)) AUDIT_RECORD;  

//��չ������ݽṹ
typedef struct tagKAudit_Record            //wdh 20110601
{
	 UINT16 NodeID;         //�ڵ���
	 UINT16 iType;          //�������
	 UINT16 ExpandNo;       //��չ�����
	 BYTE ExpandData[60];  //��չ����
	 BYTE Reserved1[6];     //�����ֶ�
	 BYTE Reserved[8];     //�����ֶ�
}__attribute__((packed)) AUDIT_EXPANDRECORD;  

/*
typedef struct tagMessagePackageHead
{
  unsigned char NodeSequence[20];
  char UserName [40];    
  unsigned char PolicyType[4];
  unsigned char PolicyVersion[8];
  UINT32 	Messagetype;
  int 		DataLenth;
} __attribute__((packed)) MESSAGE_HEAD;
//sizeof(MESSAGE_HEAD)==80
typedef struct tagMessagePackage
{
  MESSAGE_HEAD head;
  unsigned char * data;
}__attribute__((packed)) MESSAGE_PACKAGE;
//sizeof(MESSAGE_PACKAGE)==84
*/

static int innum[5] ={0};
static int denum[5] ={0};
#endif
