#ifndef VTPM_STRUCT
#define VTPM_STRUCT
#define DIGEST_SIZE 32


struct vTPM_info
{
	char uuid[DIGEST_SIZE*2];        //the uuid of vtpm,it's the same as vm
	char platform_uuid[DIGEST_SIZE*2];  // the uuid of platform,it is the same as vm's host compute node's uuid
	// the following is the environment info of vtpm
	char * ownername;
	int  tpm_type;
	UINT32 port;
	char * path;
	// the following is the passwords of owner and srk
	char * ownerpass;
	char * srkpass;
	char pubEK_uuid[DIGEST_SIZE*2];
	// the following is the wrappedkey list of vtpm“‘œ¬ «vTPMµ
	int wrappedkeynum; //the number of vtpm's wrappedkey 
	char * *wrapkey_uuid; //the index of wrappedkey
	// the following is the list of vtpm's pubKeys
	int pubkeynum; //the list of vtpm's pubKey
	char ** pubkey_uuid;//the index of vtpm's pubKey
}__attribute__((packed));

//the struct of wrappedKey


//the struct of key file data
struct keyfile_data
{
	char uuid[DIGEST_SIZE*2];
	char * filename;
	int data_size;
	char * key_data; //the file which saved the pubKey
}__attribute__((packed));

int create_physical_tpm_struct(struct vTPM_info * local_tpm,char * local_uuid,char * ownername,char * ownerpass,char * srkpass,
		char * signkey_uuid,char * pubkey_uuid);
int build_empty_physical_tpm(struct vTPM_info * local_tpm,char * local_uuid,char * ownername);
int add_pubek_to_tpm(struct vTPM_info * tpm, char * key_uuid);
int add_wrapkey_to_tpm(struct vTPM_info * tpm, char * key_uuid);
int add_pubkey_to_tpm(struct vTPM_info * tpm, char * key_uuid);
int create_vtpm_struct(struct vTPM_info * vtpm,struct vm_info * vm, char * ownerpass,char * srkpass,
		char * signkey_uuid,char * pubkey_uuid);
//void * create_key_certify_struct(void * key_cert_file,char * keyuuid,char * aikuuid);
#endif
