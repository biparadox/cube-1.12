#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
//#include <mysql/mysql.h>
#include <errno.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "../include/data_type.h"
#include "../include/struct_deal.h"
#include "../include/crypto_func.h"
#include "../include/extern_struct.h"
#include "../include/extern_defno.h"
#include "../include/message_struct.h"
#include "../include/vmlist.h"
#include "../include/vm_policy.h"
#include "../include/vtpm_struct.h"
#include "../include/connector.h"
#include "../include/logic_baselib.h"
#include "../include/connector.h"
#include "../include/sec_entity.h"

#include "local_func.h"

int load_policy_pubek(char *pubek_name)
{
	struct vTPM_publickey *pubkey;
        BYTE digest[DIGEST_SIZE];
        char buffer[DIGEST_SIZE*2];
	int retval;
	int len;
	char filename[256];

	pubkey=malloc(sizeof(struct vTPM_publickey));
        if(pubkey==NULL)
        {
                return -ENOMEM;
        }
	snprintf(filename,DIGEST_SIZE*2,"%s.pem",pubek_name);
        memset(pubkey,0,sizeof(struct vTPM_publickey));
        calculate_sm3(pubek_name,digest);
	digest_to_uuid(digest,buffer);

        memcpy(pubkey->uuid,buffer,DIGEST_SIZE*2);
        pubkey->ispubek=1;
	len=sizeof(char)*strlen(pubek_name);
	// we must add the '\0' as the name's end
	pubkey->key_filename=(char *)malloc(len+1);
        memcpy(pubkey->key_filename,pubek_name,len+1);
	retval=AddPolicy(pubkey,"PUBK");
	ExportPolicy("PUBK");

	return retval;
}

void * test_login(char * username,char * passwd)
{

	char * user_list[] = {"zhangsongge","baixin","wangyubo","hujun",NULL};
	char * passwd_list[] = {"openstack","openstack","openstack","openstack",NULL};
	struct connect_return  * return_data;
	int i=0;
	char errmsg[128];

	return_data=malloc(sizeof(struct connect_return));
	if(return_data==NULL)
		return -ENOMEM;
	memset(return_data,0,sizeof(struct connect_return));

	while(user_list[i]!=NULL)
	{
		if(strcmp(user_list[i],username)==0)
		{
			if(strcmp(passwd_list[i],passwd)==0)
			{
				return_data->retval=1;
				return return_data;
			}
			return_data->retval=-1;
			return_data->ret_data=dup_str("Error login:wrong passwd!",0);
			return_data->ret_data_size=strlen(return_data->ret_data)+1;
			return return_data;
		}
		i++;
	}
	return_data->retval=0;
	return_data->ret_data=dup_str("Error login:no such user!",0);
	return_data->ret_data_size=strlen(return_data->ret_data)+1;
	return return_data;

}

