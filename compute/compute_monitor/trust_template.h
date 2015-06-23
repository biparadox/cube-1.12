#ifndef TRUST_TEMPLATE_H
#define TRUST_TEMPLATE_H

typedef struct trust_file_info  // TF_I    single file's digest policy
{
	char uuid[DIGEST_SIZE*2];
	char * name;
	unsigned char digest[DIGEST_SIZE];
	char * info;
}__attribute__((packed)) TF_INFO;

typedef struct  trust_file_list  // TFLI  a list of file & its  digest
{
	char uuid[DIGEST_SIZE*2];
	int  pcr_index;
	int  file_num;
	unsigned char * uuid_list; 
	char * info;
	
}__attribute__((packed)) TF_LIST;

typedef struct  trust_digest_list   //TDLI
{
	char uuid[DIGEST_SIZE*2];
	int  digest_num;
	int  trust_level;
	unsigned char * digest_list; 
	char * info;
	
}__attribute__((packed)) TD_LIST;

typedef struct trust_file_array   // TFAI
{
	char uuid[DIGEST_SIZE*2];
	int  list_num;
	unsigned char * uuid_list;
	char * info;
}__attribute__((packed)) TF_ARRAY;

typedef struct trust_file_pcr_policy  // TFPP
{
	char uuid[DIGEST_SIZE*2];
	char file_list_uuid[DIGEST_SIZE*2];
	struct tcm_pcr_set pcr_set;
}__attribute__((packed)) TF_PCR;

typedef struct trust_policy_template           //TPTP
{
	char uuid[DIGEST_SIZE*2];
	char * producer;
	char * verifier;
	int  policy_num;
	char * policy_pcr_uuid;
	char * info;
}__attribute__((packed)) TP_TEMP;

typedef struct trust_policy_define           //TPDP
{
	char uuid[DIGEST_SIZE*2];
	int trust_level;
	int trust_layer;
	char * trust_area;
	char * producer;
	char * verifier;
	char * owner;
	int  policy_num;
	char * policy_set_uuid;
	char * info;
}__attribute__((packed)) TP_DEF;

typedef struct trust_arch_site          //TASI
{
	char uuid[DIGEST_SIZE*2];
	int trust_level;
	int trust_layer;
	char * trust_area;
	char * info;
}__attribute__((packed)) TA_SITE;

typedef struct trust_arch_frame           //TAFI
{
	char uuid[DIGEST_SIZE*2];
	int  policy_site_num;
	char * policy_site_uuid;
	char * info;
}__attribute__((packed)) TA_FRAME;

typedef struct trust_arch_policy           //TA_P
{
	char uuid[DIGEST_SIZE*2];
	char trust_arch_frame_uuid[DIGEST_SIZE*2];
	int  define_policy_num;
	char *define_policy_uuid;
	char * info;
}__attribute__((packed)) TA_POLICY;

#endif
