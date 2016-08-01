#ifndef VM_POLICY_H
#define VM_POLICY_H
#define DIGEST_SIZE 32
#define TPM_NUM_PCR 24
//#define CHAR_BIT    8	

struct vm_policy
{
	char uuid[DIGEST_SIZE*2];        //the uuid of vm(or physical machine)
	int  trust_level;	//vm's trust level, can be 0,1,2 or 3
	char * owner;		//vm's 	owner name
	char auth_uuid[DIGEST_SIZE*2];	//this uuid can be used to identify the vm's owner and its public identify key 
	char policy_uuid[DIGEST_SIZE*2];	// this uuid is the digest of vm's policy file
	char platform_pcr_uuid[DIGEST_SIZE*2];	// this uuid is the uuid of vm's platform, can be null if we don't care which platform the vm is in;
	char boot_pcr_uuid[DIGEST_SIZE*2];	// this uuid is the PCR value for boot step (static trust measure)
	char runtime_pcr_uuid[DIGEST_SIZE*2];	// this uuid is the value of runtime pcr 
	char * policy_describe;
}__attribute__((packed));

//the struct of wrappedKey


struct tcm_pcr_selection { 
    UINT16 size_of_select;			/* The size in bytes of the pcrSelect structure */
    BYTE * pcr_select;       /* This SHALL be a bit map that indicates if a PCR
                                                   is active or not */
}__attribute__((packed));

struct tcm_pcr_set
{
	char uuid[DIGEST_SIZE*2];        //the uuid of pcr set,it is the digests of the tcm_pcr_set's content with that the uuid set to zero
        int trust_level;
	struct tcm_pcr_selection pcr_select;
        int value_size;
	BYTE * pcr_value;
	char * policy_describe;	
}__attribute((packed));

struct policy_file
{
	char policy_uuid[DIGEST_SIZE*2];
	char policy_type[4];  // this policy's type, when use os_sec secure module, the policy type is "DIGL"
	char * creater;
	BYTE creater_auth_uuid[DIGEST_SIZE*2];
	char * policy_path;
	char file_uuid[DIGEST_SIZE*2];
	char * policy_describe;
}__attribute__((packed));

//the struct of policy file data
struct policyfile_data
{
	char uuid[DIGEST_SIZE*2];
	char * filename;
	int total_size;
	int record_no;
	int offset;
	int data_size;
	char * policy_data; //the file data
}__attribute__((packed));

//the struct of policy file data request: use type FILQ
struct policyfile_req
{
	char uuid[DIGEST_SIZE*2];
	char * filename;
	char * requestor;
}__attribute__((packed));

//the struct of policy file data request: use type FILS
struct policyfile_store
{
	char uuid[DIGEST_SIZE*2];
	char * filename;
	int file_size;
	int block_size;
	int mark_len;
	char * marks;
}__attribute__((packed));

struct verify_info  
{
	char verify_data_uuid[DIGEST_SIZE*2];
	char entity_uuid[DIGEST_SIZE*2];
	char policy_type[4];
	int trust_level;
	int info_len;
	char * info;
}__attribute__((packed));

void * build_empty_pcr_set();
int add_pcr_to_set(void * pcrs,int index,BYTE * value);
void * get_single_pcr_from_set(void * pcrs,int index);
void * build_policy_file(char * creater,char *policy_type,BYTE * key_uuid,char * filename);
#endif
