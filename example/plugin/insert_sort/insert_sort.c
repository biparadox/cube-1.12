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

#include "data_type.h"
#include "struct_deal.h"
#include "extern_struct.h"
#include "extern_defno.h"
#include "message_struct.h"
#include "logic_baselib.h"
#include "sec_entity.h"
#include "valuename.h"
#include "expand_define.h"
#include "data_define.h"

int send_int_array(int num,int * array,void * sub_proc);
int send_index_array(enum data_type type, int num,int * index,void * sub_proc);


extern struct timeval time_val={0,50*1000};

int insert_sort_init(void * sub_proc,void * para)
{
	int ret;
	// add youself's plugin init func here
	time_t seeds;
	time(&seeds);
	srand(seeds);
	return 0;
}

int insert_sort_start(void * sub_proc,void * para)
{
	int ret;
	void * recv_msg;
	int i;
	const char * type;


	for(i=0;i<3000*1000;i++)
	{
		usleep(time_val.tv_usec);
		ret=sec_subject_recvmsg(sub_proc,&recv_msg);
		if(ret<0)
			continue;
		if(recv_msg==NULL)
			continue;
		type=message_get_recordtype(recv_msg);
		if(type==NULL)
		{
			printf("message format error!\n");
			continue;
		}
		if(!find_record_type(type))
		{
			printf("message format is not registered!\n");
			continue;
		}
		proc_insert_sort(sub_proc,recv_msg);
	}

	return 0;
};

int proc_insert_sort(void * sub_proc,void * message)
{

	int i;
	int ret;
	const int size=10;
	int   value[size];
	printf("begin proc insert_sort \n");
	
	for(i=0;i<size;i++)
	{
		value[i]=rand()%256;
	}

	// web visual debug start: send array value
	send_int_array(size,value,sub_proc);
	// web visual debug end

	sleep(2);
	ret=insert_sort(size,value,sub_proc);
	return ret;
}

int insert_sort(int size, int * value,void * sub_proc)
{
	int index[2];
	int i,j;
	int ret=size;
	
	for(i=0;i<size-1;i++)
	{
		j=i+1;
		int temp = value[j];
		if(value[j]<value[i])
		{
			while(temp<value[i])
			{
				value[i+1]=value[i];
				// web visual debug start:
				index[0]=i;
				index[1]=i+1;
				send_index_array(DATA_SWAP,2,index,sub_proc);			
				//web visual debug end
				i--;
				if(i<0)
					break;
				usleep(1000*500);
			}
			value[i+1]=temp;
		}
		else
		{
				usleep(1000*500);
		}
		i=j-1;
		usleep(1000*500);
	}	
	return ret;
}
