#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include "readconfig.h"

int read_arg(FILE * stream, char ** arg)
	/*  Read a line from a config file 
	 *  stream: the config file stream
	 *  arg: the return values,
	 *     arg array need at least MAX_ARG_NUM*sizeof(char *) space
	 *     the arg[0] must point to a free space which 
	 *     has least MAX_LINE_LEN BYTES space
	 *  
	 *  return value: read arg numbers,0  if no arg read, 
	 *  negative value if it has special error   
	 *  */
{
	char buffer[MAX_LINE_LEN];
	int argnum,i,j;
	char * ret;
	char c;
	
	for(i=1;i<MAX_ARG_NUM;i++)
		arg[i]=NULL;
	 /* Read the Line  */
	ret=fgets(buffer,MAX_LINE_LEN,stream);
	if(ret==NULL)
		return -ENODATA; 
	if(buffer[0]=='#')   
       	/*First character is '#' means it is a comet line*/
		return 0;	
	argnum=0;
	i=0;
	
	do {
		/*find the first valid character */
		while( (buffer[i] == ' ') || buffer[i]=='\t')
			i++;
		c=buffer[i];	
		if((buffer[i]==0)||(buffer[i]=='\n'))
			return argnum;

		/* Read the argument from the config file */
	
		if(c=='\"'){    /* argument is in the " " */
			/*  perhaps there are some space in the argument */
		
			j=0;
			i++;
			c=buffer[i];
			do {
				if((c==0)||(c=='\n'))
					return -EINVAL;
			        arg[argnum][j++]=c;	
				if(j>MAX_FILENAME_LEN)
					return -ENAMETOOLONG;
				c=buffer[++i];
			}while(c!='\"');
			arg[argnum++][j]=0;	
			arg[argnum]=arg[argnum-1]+j+1;
			i++;
		}
		else {         /* file name is a string without space */
			j=0;
			do {
			        arg[argnum][j++]=c;	
				if(j>MAX_FILENAME_LEN)
					return -ENAMETOOLONG;
				c=buffer[++i];
				if((c==0)||(c=='\n'))
				{
					arg[argnum++][j]=0;	
					return argnum;
				}
			}while((c!=' ') &&(c!='\t'));
			arg[argnum++][j]=0;	
			arg[argnum]=arg[argnum-1]+j+1;
			arg[argnum][0]=0;
		}
		if(argnum >= MAX_ARG_NUM)
			return -E2BIG;
	}while(1);
	return 0;	
}
/*
int main(void)
{
	const char * config_filename= "../local/execlist.txt";
	char *arg[ MAX_ARG_NUM ];
	char buffer[ MAX_LINE_LEN ];
	int i,recordnum;
	int ret;
	FILE * fp;
	
	arg[0]=buffer;

	fp=fopen(config_filename,"r");
	if(fp==NULL)
	  return -ENOENT;
	
	do {
		ret=read_arg(fp,arg);
		
		if(ret<0){
			printf("\nread file finished!\n");
			fclose(fp);
			return 0;
		}
		if(ret==0) 
			continue;
		if(ret>MAX_ARG_NUM)
			return -ENODATA;
		int i;
		printf("\n  ");
		for(i=0;i<ret;i++)
			printf("%s  ",arg[i]);
	}while(1);
	fclose(fp);
     	return 0;
}*/
