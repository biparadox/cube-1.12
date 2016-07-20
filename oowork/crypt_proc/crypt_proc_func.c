#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <dirent.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

#include "../include/data_type.h"
#include "../include/struct_deal.h"
#include "../include/crypto_func.h"
#include "../include/extern_struct.h"
#include "../include/extern_defno.h"
#include "../include/valuename.h"
#include "../include/message_struct.h"
#include "../include/message_struct_desc.h"
#include "../include/vmlist.h"
#include "../include/vtpm_struct.h"
#include "../include/vm_policy.h"
#include "../include/connector.h"
#include "../include/logic_baselib.h"
#include "../include/connector.h"
#include "../include/sec_entity.h"
#include "../include/tesi.h"
#include "../include/main_proc_init.h"

#include "main_proc_func.h"

int crypt_proc_init()
{
	int ret;
	return 0;
}

int privkey_memdb_init(char * type, void * para)
{
	int ret;
	char * privkey_dirname="privkey";
	char namebuf[512];
	struct vTPM_wrappedkey * privkey;
	DIR * privkey_dir;
	int key_no=0;


	privkey_dir=opendir(privkey_dirname);
	if(privkey_dir==NULL)
	{
		return -EINVAL;
	}
	struct dirent * dentry;
	while((dentry=readdir(privkey_dir))!=NULL)
	{
		if(dentry->d_type !=DT_REG)
			continue;
		// check if file's tail is string ".key"
		int namelen=strlen(dentry->d_name);
		if(namelen<=4)
			continue;
		char * tail=dentry->d_name+namelen-4;
		if(strcmp(tail,".key")!=0)
			continue;
		strcpy(namebuf,privkey_dirname);
		strcat(namebuf,"/");
		strncat(namebuf,dentry->d_name,namelen-4);

		privkey=malloc(sizeof(struct vTPM_wrappedkey));
		if(privkey==NULL)
			return -ENOMEM;

		ret = create_blobkey_struct(privkey,NULL,NULL,"kkk",namebuf);
		if(ret<0)
			return ret;
		AddPolicy(privkey,"BLBK");
		key_no++;
	}
       	ExportPolicy("BLBK");
	printf("read %d privkey!\n",key_no);
	return key_no;
}
int pubkey_memdb_init(char * type, void * para)
{
	int ret;
	char * pubkey_dirname="pubkey";
	char namebuf[512];
	struct vTPM_publickey * pubkey;
	DIR * pubkey_dir;
	int key_no=0;


	pubkey_dir=opendir(pubkey_dirname);
	if(pubkey_dir==NULL)
	{
		return -EINVAL;
	}
	struct dirent * dentry;
	while((dentry=readdir(pubkey_dir))!=NULL)
	{
		if(dentry->d_type !=DT_REG)
			continue;
		// check if file's tail is string ".pem"
		int namelen=strlen(dentry->d_name);
		if(namelen<=4)
			continue;
		char * tail=dentry->d_name+namelen-4;
		if(strcmp(tail,".pem")!=0)
			continue;
		strcpy(namebuf,pubkey_dirname);
		strcat(namebuf,"/");
		strncat(namebuf,dentry->d_name,namelen-4);

		pubkey=malloc(sizeof(struct vTPM_publickey));
		if(pubkey==NULL)
			return -ENOMEM;

		ret = create_pubkey_struct(pubkey,NULL,NULL,namebuf);
		if(ret<0)
			return ret;
		AddPolicy(pubkey,"PUBK");
		key_no++;
	}
       	ExportPolicy("PUBK");
	printf("read %d pubkey!\n",key_no);
	return key_no;
}
