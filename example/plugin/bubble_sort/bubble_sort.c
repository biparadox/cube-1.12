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

int send_int_array(char* name,int num,int * array,void * sub_proc);
int send_index_array(char * name,enum data_type type, int num,int * index,void * sub_proc);


extern struct timeval time_val={0,50*1000};

int bubble_sort_init(void * sub_proc,void * para)
{
	int ret;
	// add youself's plugin init func here
	time_t seeds;
	time(&seeds);
	srand(seeds);
	return 0;
}

int bubble_sort_start(void * sub_proc,void * para)
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
		proc_bubble_sort(sub_proc,recv_msg);
	}

	return 0;
};

int proc_bubble_sort(void * sub_proc,void * message)
{

	int i;
	int ret;
	const int size=10;
	int   value[size];
	printf("begin proc bubble_sort \n");
	
	for(i=0;i<size;i++)
	{
		value[i]=rand()%256;
	}

	// web visual debug start: send array value
	send_int_array("bubble",size,value,sub_proc);
	// web visual debug end

	sleep(2);
	ret=bubble_sort(size,value,sub_proc);
	return ret;
}

int bubble_sort(int size, int * value,void * sub_proc)
{
	int index[2];
	int i,j;
	int ret=size;
	
	for(i=size;i>0;i--)
	{
		for(j=0;j<i-1;j++)
		{
			int temp;
			// web visual debug start: record curr bubble sort site
			index[0]=j;index[1]=j+1;
			// web visual debug end

			if(value[j]>value[j+1])
			{	
				temp=value[j];value[j]=value[j+1];value[j+1]=temp;
				// web visual debug start:
				send_index_array("bubble",DATA_SWAP,2,index,sub_proc);			
				//web visual debug end
			}
			else
			{
				// web visual debug start:
				send_index_array("bubble",DATA_KEEP,2,index,sub_proc);			
				//web visual debug end
			}
			usleep(1000*500);
		}	
		usleep(1000*500);
	}
	return ret;
}
