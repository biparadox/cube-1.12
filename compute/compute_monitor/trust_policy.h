#ifndef TRUST_POLICY_H
#define TRUST_POLICY_H

enum trust_format_enum
{
	TF_NULL   = 0,
	TF_ENTITY =1000,
	TF_OBJECT =1101,
	TF_MBR,
	TF_FILE,
	TF_LIST,
	TF_CHECK,
	TF_DIGEST,
	TF_PCRS,
	TF_SUBJECT=1201,
	TF_USER,
	TF_ROLE,
	TF_PROC,
	TF_PORT,
	TF_CHANNEL,
	TF_HOLE,
	TF_ARRAY,
	TF_FRAME,
	TF_POLICY=1301,
	TF_AUDIT=1401,
	TF_TRUST,
	TF_SET=1501,
};

enum trust_set_type_enum
{
	TS_FUNCTION_SET,
	TS_MECHANISM_SET,
	TS_POLICY_SET,
	TS_SUPPORT_SET,
	TS_COMP_AREA,
	TS_DOM_BOUNDARY,
	TS_COMM_CONN,
	TS_CHOICE_SET,
	TS_MIX_SET,
	TS_SEC_SYSTEM,
};
enum trust_policy_type_enum
{
	TP_ORIGIN_POLICY,
	TP_VERIFY_POLICY,
	TP_DEPLOYMENT_POLICY,
	TP_RUNNING_POLICY,
};

enum trust_flag_enum
{
	TF_TRUST_STATIC = 0x01,
	TF_TRUST_DYNAMIC = 0x02,
	TF_TRUST_AND = 0x10,
	TF_TRUST_OR = 0x20 ,
	TF_TRUST_NOT = 0x40,
};
 

typedef struct trust_policy_head
{
	char uuid[DIGEST_SIZE*2];
	int  main_type;    // key value
	int  sub_type;     // key value
	int  set_flag;   
	char name[DIGEST_SIZE*2];
	int  format_size;
}__attribute__((packed)) TP_HEAD;

typedef struct trust_policy
{
	TP_HEAD policy_head;
	void * policy_desc;
	void * policy_set;	
	void * trust_attr;	
}__attribute__((packed)) T_POLICY;

struct trust_mbr_info     // 
{
	char * dev_name;
	unsigned char digest[DIGEST_SIZE];
	char * info;
}__attribute__((packed));

struct trust_file_info  // TF_I    single file's digest policy
{
	char * file_name;
	unsigned char digest[DIGEST_SIZE];
	char * info;
}__attribute__((packed));

struct  trust_file_list  // TFLI  a list of file & its  digest
{
	int  file_num;
	unsigned char * uuid_list; 
	char * info;
}__attribute__((packed));

struct  trust_check_info  // TFLI  a list of file & its  digest
{
	int  check_data_length;
	unsigned char * check_data; 
	char * info;
}__attribute__((packed));

typedef struct  trust_digest   //TDLI
{
	unsigned char digest[DIGEST_SIZE]; 
	char * info;
}__attribute__((packed)) ;

typedef struct  trust_digest_list   //TDLI
{
	int  digest_num;
	unsigned char * digest_list; 
	char * info;
}__attribute__((packed)) ;

typedef struct trust_set_info   // TFAI
{
	int  list_num;
	unsigned char * uuid_list;
	char * info;
}__attribute__((packed)) TP_SET;

typedef struct trust_policy_info           //TPTP
{
	char * producer;
	char * verifier;
	int  policy_num;
	char * policy_pcr_uuid;
	char * info;
}__attribute__((packed)) TP_TEMP;

typedef struct trust_policy_define           //TPDP
{
	UINT32 trust_type;
	UINT32 trust_level;
	UINT32 trust_layer;
	char * trust_area;
	char * producer;
	char * verifier;
	char * owner;
	char * info;
}__attribute__((packed)) TP_DEF;

typedef struct trust_arch_site          //TASI
{
	int trust_level;
	int trust_layer;
	char * trust_area;
	char * info;
}__attribute__((packed)) TA_SITE;

typedef struct trust_arch_frame           //TAFI
{
	int  policy_site_num;
	char * policy_site_uuid;
	char * info;
}__attribute__((packed)) TA_FRAME;

typedef struct trust_arch_policy           //TA_P
{
	char trust_arch_frame_uuid[DIGEST_SIZE*2];
	int  define_policy_num;
	char *define_policy_uuid;
	char * info;
}__attribute__((packed)) ;

struct tcm_pcr_selection { 
    UINT16 size_of_select;			/* The size in bytes of the pcrSelect structure */
    BYTE * pcr_select;       /* This SHALL be a bit map that indicates if a PCR
                                                   is active or not */
}__attribute__((packed));


struct tcm_pcr_composite { 
    struct tcm_pcr_selection pcr_select;
    int value_size;
    BYTE * pcr_value;
}__attribute__((packed));


struct trust_pcr_set
{
	struct tcm_pcr_composite pcrs; // key value
	char * info;	
}__attribute((packed));

void * build_empty_pcr_set();
int add_pcr_to_set(void * pcrs,int index,BYTE * value);
void * get_single_pcr_from_set(void * pcrs,int index);
#endif
