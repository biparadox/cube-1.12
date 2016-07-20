#include <stdlib.h>
#include <string.h>

//#include "common.h"
//#include "tesi.h"
#include "../include/struct_deal.h"
#include "../include/extern_struct.h"
#include "../include/extern_struct_desc.h"
#include "../logic_baselib.h"
#include "../include/vtpm_struct.h"
#include "../include/vtpm_desc.h"
//#include "logic_vtpm.h"


BYTE Blob[4096];
char text[4096];
int main()
{
	char                    *function = "Tspi_TESI_Init";
/*	
        TSS_RESULT              result;
        TSS_HKEY                hCAKey;
        TSS_HKEY                hSignKey;
        TSS_HKEY                hReloadKey;
        TSS_HKEY                hReloadPubKey;
	*/
	int retval;
/*
        result=TESI_Local_Reload();

        if ( result != TSS_SUCCESS )
        {
                if( !(checkNonAPI(result)) )
                {
                        print_error( function, result );
                }
                else
                {
                        print_error_nonapi( function, result );
                }
        }
        else
        {
                print_success( function, result );
        }
        result=TESI_Local_GetPubKeyFromCA(&hCAKey,"CA");
        result=TESI_Local_CreateSignKey(&hSignKey,(TSS_HKEY)NULL,"sss","kkk");
        if(result == TSS_SUCCESS)
                printf("Create SignKey SUCCEED!\n");

        TESI_Local_WriteKeyBlob(hSignKey,"testsignkey");
        TESI_Local_WritePubKey(hSignKey,"testsignkey");	
	*/
	static struct vTPM_wrappedkey wrap_key;
//	wrap_key=malloc(sizeof(struct vTPM_wrappedkey));
	strcpy(wrap_key.uuid,"7a867c66eeab4287f221bc8a1477a1015e149695");
	strcpy(wrap_key.vtpm_uuid,"a02c5416-37cb-4266-9e17-2e45a3db6e79");
	
	wrap_key.issrkwrapped=1;
	wrap_key.key_type=1;//hSignKey   --ask if it needs which number corresbonds the key
	wrap_key.key_alg=1;//algorithm
	wrap_key.key_size=1024;
	strcpy(wrap_key.key_binding_policy_uuid,"fcbb2ddddd918fd0e0b9c5bc34263a0a070179392");
	strcpy(wrap_key.wrapkey_uuid,"048b0ae0a32529ad0b69c539d4cb6282d3d4f86a3");
	wrap_key.keypass=(char *)malloc(sizeof(char)*4);
	strcpy(wrap_key.keypass,"kkk");
	wrap_key.key_filename=(char *)malloc(sizeof(char)*16);
	strcpy(wrap_key.key_filename,"testsignkey.key");


	printf("test 1!\n");
	int k;

	void *policy;
	int i;
	logic_baselib_init();

        register_record_type("BLBK",wrappedkey_desc);
        register_policy_lib("BLBK",&wrappedkey_lib_ops);

	
	retval=LoadPolicyFromFile("wrap_key.lib","BLBK");
	printf("test load!\n");
	k=AddPolicy(wrap_key,"BLBK");
	printf("test add %x!\n",&wrap_key);
	policy=GetFirstPolicy("BLBK");
	printf("test getfirst outside addr %x!\n",policy);
        i=0;
        while(policy!=NULL)
        {
		printf("test output addr %x!\n",policy);
                OutPutPolicy(policy,"BLBK");
                printf("\n");
                policy=GetNextPolicy("BLBK");
                i++;
        }       
        
	//char *buff;
	//buff=(char *)malloc(sizeof(wrap_key));
	//memcpy(buff,&wrap_key,sizeof(wrap_key));
	//printf("%s",buff);
	//void *policy;
	//policy=BuildPolicy(buff,"BLBK");
	//AddPolicy(policy,"BLBK");
	
	
//	struct struct_elem_attr * test_desc;
//	void * struct_template;
//	POLICY_PROTOCOL  Protocol;

//	char * string;
//	int bloboffset;
//	int stroffset;
/*	int i;
	int retval;
	char * policy_package;


//	void * obj_policy_lib;
	void * policy;
	logic_baselib_init();

	register_policy_lib("BLBK",wrappedkey_desc,&wrappedkey_lib_ops);
	retval=LoadTxtPolicyFile("blbklist.txt","BLBK",&policy_package);
	retval=LoadPolicyData(policy_package);
	free(policy_package);

	policy=GetFirstPolicy("BLBK");
	i=0;
	while(policy!=NULL)
	{
		OutPutPolicy(policy,"BLBK");
		printf("\n");
		policy=GetNextPolicy("BLBK");
		i++;
	}	
	
	ExportPolicyToFile("wrappedkey.lib","BLBK");
*/
   //   ExportPolicyToFile("wrap_key.lib","BLBK");
	return 0;
}

