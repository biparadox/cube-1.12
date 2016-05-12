
#include<stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

//#include  "../include/kernel_comp.h"
//#include "../list.h"

#include "../include/data_type.h"
#include "../include/sysfunc.h"

char *  get_temp_filename(char * tag )
{
	char buf[128];
	int len;
	pid_t pid=getpid();
	sprintf(buf,"/tmp/temp.%d",pid);
	len=strlen(buf);
	if(tag!= NULL)
	{
		len+=strlen(tag);
		if(strlen(tag)+strlen(tag)>=128)
			return -EINVAL;
		strcat(buf,tag);
	}
	char * tempbuf = malloc(len+1);
	if(tempbuf==NULL)
		return -EINVAL;
	memcpy(tempbuf,buf,len+1);
	return tempbuf;
}
	
int get_local_uuid(char * uuid)
{
	FILE *fi,*fo;
	int i=0;
	char *s,ch;
	int len;

	char cmd[128];
	char *tempfile1,*tempfile2;

	tempfile1=get_temp_filename(".001");
	if((tempfile1==NULL) || IS_ERR(tempfile1)) 
		return tempfile1;

/*	sprintf(cmd,"df | sed -n \'/\\/$/w %s\'",tempfile1);
	system(cmd);
	fi=fopen(tempfile1,"r");
	ch=fgetc(fi);
	while(ch!=' ')
	{
		i++;	
		ch=fgetc(fi);
	}
	s=(char *)malloc(i);
	fseek(fi,0,SEEK_SET);
	fread(s,1,i,fi);
	fclose(fi);

	fo=fopen(tempfile1,"w");
	fwrite(s,1,i,fo);
	fclose(fo);
	free(s);

	tempfile2=get_temp_filename(".001");
	if((tempfile2==NULL) || IS_ERR(tempfile2)) 
		return tempfile2;

	sprintf(cmd,"cat %s | sed -n \'s/\\//\\\\\\//gw %s\'",tempfile1,tempfile2);
	system(cmd);*/
	sprintf(cmd,"dmidecode | grep UUID | awk '{print $2}' > %s",tempfile1);
	system(cmd);

	fi=fopen(tempfile1,"r");
	/*int k;
	k=i+8;
	fseek(fi,k,SEEK_SET);*/
	memset(uuid,0,DIGEST_SIZE*2);
	len=fread(uuid,1,36,fi);
	//printf("uuid=%s",uuid);
	//sprintf(cmd,"rm -f %s %s",tempfile1,tempfile2);
	sprintf(cmd,"rm -f %s",tempfile1);
	system(cmd);
	return len;

}

int mount_image(char * imagepath,char * device,char *mountpoint)
{
	char cmd[512];
	int ret;
	sprintf(cmd,"qemu-nbd -c %s %s",device,imagepath);
	ret=system(cmd);
	if(ret<0)
		return ret;
	
	sleep(2);
	sprintf(cmd, "mount -o ro %sp1 %s",device,mountpoint);
	ret=system(cmd);
	if(ret<0)
	{
		sprintf(cmd, "qemu-nbd -d %s",device);
		system(cmd); 
		return ret;
	}
	//sleep(1);
	return 0;
}

int umount_image(char * device,char *mountpoint)
{
	char cmd[512];
	int ret;
	sprintf(cmd,"umount -l %s",mountpoint);
	ret=system(cmd);
	sleep(5);
	sprintf(cmd,"qemu-nbd -d %s",device);
        ret=system(cmd);
	return ret;
}
