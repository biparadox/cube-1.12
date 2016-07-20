#include <stdlib.h>
#include <string.h>

#include "../include/data_type.h"
#include "../include/struct_deal.h"
#include "../include/extern_struct.h"
#include "../include/extern_struct_desc.h"
#include "../include/logic_baselib.h"
#include "../include/vtpm_struct.h"
#include "../include/vtpm_desc.h"
#include "../include/tesi_key.h"
#include "../include/tesi_key_desc.h"
#include "../include/vm_policy_desc.h"
//#include "logic_vtpm.h"


BYTE Blob[4096];
char text[4096];
char local_uuid[DIGEST_SIZE*2];
char * proc_name="test_main";

int main()
{
	
	struct struct_elem_attr * test_desc;
	void * struct_template;

	char * string;
	int bloboffset;
	int stroffset;
	int i;
	int retval;
	char * policy_package;

	/*

	memcpy(&(Protocol.Head.Protocol),"PLCY",4);
	Protocol.Head.Version=0;
	memcpy(&(Protocol.Head.Type),"OBJL",4);
	Protocol.Head.Flags=0;
	Protocol.Head.DataLength=80;
	Protocol.Head.eType=0;
	Protocol.Head.ExpandLength=20;
	Protocol.Head.Reserved=0xffffffff;
	Protocol.Data=(BYTE *)malloc(80);
	Protocol.eData=(BYTE *)malloc(20);

	for(i=0;i<Protocol.Head.DataLength;i++)
	{
		Protocol.Data[i]='0'+i;
	}
	
	for(i=0;i<Protocol.Head.ExpandLength;i++)
	{
		Protocol.eData[i]='z'-i;
	}

	//test_desc=clone_struct_desc(Policy_Protocol_desc);	
	struct_template=create_struct_template(Policy_Protocol_desc);
//	Blob=malloc(4096);
//	text=malloc(4096);
	string=text;
	bloboffset=struct_2_blob(&Protocol,Blob,struct_template);
	printf("get a %d blob with a struct!\n",bloboffset);

	bloboffset = blob_2_text(Blob,&string,struct_template);

	printf("use a %d blob to generate text!\n",bloboffset);

	stroffset=0;

	printf("%s\n",text);
	memset(Blob,0,4096);

	text_2_blob(text,Blob,struct_template,&stroffset);
	printf("get a %d blob with a text!\n",bloboffset);

	bloboffset=blob_2_struct(Blob,&Protocol,struct_template);
	printf("rebuild struct  with a blob offset!\n",bloboffset);

	bloboffset=struct_2_blob(&Protocol,Blob,struct_template);
	printf("get a %d blob with a struct!\n",bloboffset);

	string=text;
	bloboffset = blob_2_text(Blob,&string,struct_template);

	printf("use a %d blob to generate text!\n",bloboffset);

	printf("%s\n",text);
	free_struct_template(struct_template);
//	free(Blob);
//	free(text);
	*/

	void * obj_policy_lib;
	void * policy;
	int ret;
	logic_baselib_init();
	struct_template=create_struct_template(policyfile_data_desc);
	void * pcrs=build_empty_pcr_set();

/* 	
	register_policy_lib("OBJL",OBJ_LABEL_desc,&objlabel_policy_ops);
	LoadTxtPolicyFile("objlist.txt","OBJL",&policy_package);
	LoadPolicyData(policy_package);
	free(policy_package);

	policy=GetFirstPolicy("OBJL");
	i=0;
	while(policy!=NULL)
	{
		OutPutPolicy(policy,"OBJL");
		printf("\n");
		policy=GetNextPolicy("OBJL");
		i++;
	}	
*/	

	register_record_type("BLBK",&wrappedkey_desc);
	register_policy_lib("BLBK",&general_lib_ops);
	retval=LoadTxtPolicyFile("blbklist.txt","BLBK",&policy_package);
	retval=LoadPolicyData(policy_package);
	free(policy_package);

	ret=GetFirstPolicy(&policy,"BLBK");
	i=0;
	while(policy!=NULL)
	{
		printf("\n");
		void * policy1=DupPolicy(policy,"BLBK");
		OutPutPolicy(policy1,"BLBK");
		ret=GetNextPolicy(&policy,"BLBK");
		i++;
	}	
	
	ExportPolicyToFile("wrappedkey.lib","BLBK");

	return 0;
}

