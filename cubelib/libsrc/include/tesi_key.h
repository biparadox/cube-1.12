#ifndef KEY_CERTIFY_H
#define KEY_CERTIFY_H

enum    tpm_aik_state
{
	AIK_STATE_INIT,
	AIK_STATE_REQ,
	AIK_STATE_VERIFY,
	AIK_STATE_KEYPREPARE,
	AIK_STATE_FAIL,
};

struct vTPM_wrappedkey
{
	char uuid[DIGEST_SIZE*2];
	char vtpm_uuid[DIGEST_SIZE*2];
	int issrkwrapped; //flag which indices if the key is wrapped by srk
	int key_type; //the type of key,such as  STORAGE_KEY,SIGN_KEY
	int key_alg; //the key algorithm
	int key_size; // the size of key
	char key_binding_policy_uuid[DIGEST_SIZE*2]; //if the key is wrappedKey,it is setted by uuid of binding policy 
	char wrapkey_uuid[DIGEST_SIZE*2]; //the uuid of key;if the key is srk,uuid should be setted by the uuid of vtpm
	int  keydigestsize;
	char * pubkeydigest;
	char * keypass; //the password of key
	char * key_filename; //the file which saves the key
}__attribute__((packed));

//the struct of pubKey
struct vTPM_publickey
{
	char uuid[DIGEST_SIZE*2];
	char vtpm_uuid[DIGEST_SIZE*2];
	int ispubek; //flag which decides if the pubkey is pubEK
	int key_type; //type of key,such as STORAGE_KEY,SIGN_KEY
	int key_alg; //key algorithm
	int key_size; // size of key
	char key_binding_policy_uuid[DIGEST_SIZE*2]; //if the corresponding privateKey of the pubEK is bindkey,it should save the uuid of bind policy 
	char privatekey_uuid[DIGEST_SIZE*2]; //the corresponding privatedKey's of pubKey,if the pubKey is pubEK,the uuid should be set by uuid of vtpm
	int  keydigestsize;
	char * pubkeydigest;
	char * keypass; //the password of key
	char * key_filename; //the file which saved the pubKey
}__attribute__((packed));

typedef struct tagtpm_key_certify_info   // KEY CERTIFO
{
	char uuid[DIGEST_SIZE*2];
	char keyuuid[DIGEST_SIZE*2];
	char aikuuid[DIGEST_SIZE*2];
    	UINT16       keyusage;
    	UINT16	     keyflags;
    	BYTE authdatausage;
	int  keydigestsize;
	BYTE *pubkeydigest;
	int PCRinfosize;
	BYTE * PCRinfos;	
	char * filename;

}__attribute((packed)) KEY_CERT;

void * create_key_certify_struct(void * key_cert_file,char * keyuuid,char * aikuuid);
int create_blobkey_struct(struct vTPM_wrappedkey * blobkey,char * wrapkey_uuid,char * vtpm_uuid,char * keypass,char * keyfile);
int create_pubkey_struct(struct vTPM_publickey * pubkey,char * privatekey_uuid,char * vtpm_uuid,char * keyfile);
//void * verify_key_certify_struct(void * key_cert_file,char * keyuuid,char * aikuuid);

#endif
