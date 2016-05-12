#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "../include/data_type.h"
#include "../include/struct_deal.h"
#include "../include/vm_policy.h"
#include "../include/vm_policy_desc.h" 
#include "../include/crypto_func.h" 


BYTE Blob[4096];
char text[4096];
struct vm_policy * vmpolicy;
struct policy_file * policy;
struct tcm_pcr_set * pcr_set;
void * struct_template;
int main()
{
	
	struct struct_elem_attr * test_desc;

	char * string;
	int bloboffset;
	int stroffset;
	int i;
	int retval;

	int fd;
	struct stat statbuf;
	int recordsize;

	BYTE digest[DIGEST_SIZE];


	printf("%d\n",sizeof(vmpolicy));
	
//	struct_template=create_struct_template(vm_policy_desc);


	struct_template=create_struct_template(tcm_pcr_set_desc);
	calculate_sm3("test_main.c",digest);
	void * pcrs;
	pcrs=build_empty_pcr_set();
	add_pcr_to_set(pcrs,1,digest);
	bloboffset=struct_2_blob(pcrs,Blob,struct_template);
	printf("get a %d blob with a struct!\n",bloboffset);
	string=text;
	stroffset=0;
	bloboffset = blob_2_text(Blob,string,struct_template,&stroffset);

	printf("use a %d blob to generate text again!\n",bloboffset);

	printf("%s\n",text);

	calculate_sm3("test_vmstruct.c",digest);
	add_pcr_to_set(pcrs,3,digest);

	bloboffset=struct_2_blob(pcrs,Blob,struct_template);
	printf("get a %d blob with a struct!\n",bloboffset);
	string=text;
	stroffset=0;
	bloboffset = blob_2_text(Blob,string,struct_template,&stroffset);
	printf("use a %d blob to generate text again!\n",bloboffset);
	printf("%s\n",text);

	
	calculate_sm3("test_vmstruct",digest);
	add_pcr_to_set(pcrs,2,digest);
	bloboffset=struct_2_blob(pcrs,Blob,struct_template);
	printf("get a %d blob with a struct!\n",bloboffset);
	string=text;
	stroffset=0;
	bloboffset = blob_2_text(Blob,string,struct_template,&stroffset);
	printf("use a %d blob to generate text again!\n",bloboffset);
	printf("%s\n",text);

	
	calculate_sm3("test_main1.c",digest);
	add_pcr_to_set(pcrs,9,digest);

	bloboffset=struct_2_blob(pcrs,Blob,struct_template);
	printf("get a %d blob with a struct!\n",bloboffset);
	string=text;
	stroffset=0;
	bloboffset = blob_2_text(Blob,string,struct_template,&stroffset);
	printf("use a %d blob to generate text again!\n",bloboffset);
	printf("%s\n",text);

	free_struct_template(struct_template);
	
	memset(text,0,4096);

	policy=build_policy_file("administator","DIGL",NULL,"test_main2.c");

	struct_template=create_struct_template(policy_file_desc);
	bloboffset=struct_2_blob(policy,Blob,struct_template);
	printf("get a %d blob with a struct!\n",bloboffset);
	string=text;
	stroffset=0;
	bloboffset = blob_2_text(Blob,string,struct_template,&stroffset);
	printf("use a %d blob to generate text again!\n",bloboffset);
	printf("%s\n",text);

	free_struct_template(struct_template);
	
	return 0;
	
}

