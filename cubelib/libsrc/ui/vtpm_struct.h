#define DIGEST_SIZE 32

struct vTPM_info
{
	char uuid[DIGEST_SIZE*2];        //the uuid of vtpm
	// the following is the environment info of vtpm
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
	char * keypass; //the password of key
	char * key_filename; //the file which saved the pubKey
}__attribute__((packed));
