#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "../include/struct_deal.h"
#include "vmlist.h"
#include "vmlist_desc.h"


BYTE Blob[4096];
char text[4096];
struct info vminfo;
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


	printf("%d\n",sizeof(vminfo));
	//test_desc=clone_struct_desc(Policy_Protocol_desc);	
	
//      create struct template;
	struct_template=create_struct_template(vminfo_desc);
//	Blob=malloc(4096);
//	text=malloc(4096);

	fd=open("vmlist.txt",O_RDONLY);
	if(fd<0)
	{
		printf("can't open txt policy file! \n");
		return -EACCES;
	}
	
	if(fstat(fd,&statbuf)<0)

	{
		printf("fstat error\n");
		return -2;
	}	
	recordsize = statbuf.st_size;

 	// read string
	//
	if(read(fd,text,recordsize)!=	recordsize)
	{
		printf("read vm list error! \n");
		return -EINVAL;
	}
	
	string=text;

	stroffset=0;

	printf("%s\n",text);
	memset(Blob,0,4096);

	bloboffset=text_2_blob(text,Blob,struct_template,&stroffset);
	printf("get a %d blob with a text!\n",bloboffset);

	string=text;
	stroffset=0;
	bloboffset = blob_2_text(Blob,string,struct_template,&stroffset);

	printf("use a %d blob to generate text!\n",bloboffset);

	printf("%s\n",text);

	bloboffset=blob_2_struct(Blob,&vminfo,struct_template);
	printf("rebuild struct  with a blob offset!\n",bloboffset);

	bloboffset=struct_2_blob(&vminfo,Blob,struct_template);
	printf("get a %d blob with a struct!\n",bloboffset);

	string=text;
	stroffset=0;
	bloboffset = blob_2_text(Blob,string,struct_template,&stroffset);

	printf("use a %d blob to generate text again!\n",bloboffset);

	printf("%s\n",text);
	free_struct_template(struct_template);
//	free(Blob);
//	free(text);
	

	return 0;
	
}

