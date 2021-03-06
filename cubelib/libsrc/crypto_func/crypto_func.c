#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
//#include "common.h"
#include "../include/data_type.h"
//#include "../list.h"
#include "sm3.h"
#include "sm4.h"
#include "sha1.h"
#include "../include/crypto_func.h"

//int file_to_hash(int argc, char *argv[])
int digest_to_uuid(BYTE *digest,char *uuid)
{
	int i,j,k,retval;
	unsigned char char_value;
	retval=DIGEST_SIZE;
	k=0;
	for(i=0;i<retval;i++)
	{
		int tempdata;
		char_value=digest[i];

		for(j=0;j<2;j++)
		{
			tempdata=char_value>>4;
			if(tempdata>9)
				*(uuid+k)=tempdata-10+'a';
			else
				*(uuid+k)=tempdata+'0';
			k++;
			if(j!=1)
				char_value<<=4;
				
		}
	}
	return 0;
}
#define PCR_SIZE 20
int extend_pcr_sm3digest(BYTE * pcr_value,BYTE * sm3digest)
{
	BYTE buffer[DIGEST_SIZE*2];
	BYTE digest[DIGEST_SIZE];
	memcpy(buffer,pcr_value,PCR_SIZE);
	memcpy(buffer+PCR_SIZE,sm3digest,DIGEST_SIZE);
	calculate_context_sha1(buffer,PCR_SIZE+PCR_SIZE,digest);
//	calculate_context_sha1(buffer,PCR_SIZE+DIGEST_SIZE,digest);
	memcpy(pcr_value,digest,PCR_SIZE);
	return 0;
}

int comp_proc_uuid(char * dev_uuid,char * name,char * conn_uuid)
{
	int len;
	int i;
	BYTE buffer[DIGEST_SIZE*4];
	BYTE digest[DIGEST_SIZE];
	memset(buffer,0,DIGEST_SIZE*4);
	len=strlen(dev_uuid);
	if(len<DIGEST_SIZE*2)
		memcpy(buffer,dev_uuid,len);
	else
		memcpy(buffer,dev_uuid,DIGEST_SIZE*2);
	if(name!=NULL)
	{
		len=strlen(name);
		if(len<DIGEST_SIZE*2)
		{
			memcpy(buffer+DIGEST_SIZE*2,name,len);
		}
		else 
		{
			memcpy(buffer+DIGEST_SIZE*2,name,DIGEST_SIZE*2);
		}
	}
	calculate_context_sm3(buffer,DIGEST_SIZE*4,digest);
	digest_to_uuid(digest,conn_uuid);
	return 0;
}
static inline int _get_lowest_bit(long long value)
{
	int i;
	int ret=0;
	int offset=sizeof(long long)*8/2;

	long long mask[6]=
	{
		0x00000000FFFFFFFF,
		0x0000FFFF0000FFFF,
		0x00FF00FF00FF00FF,
		0x0F0F0F0F0F0F0F0F,
		0x3333333333333333,
		0x7777777777777777,
	};
//	long long mask=-1;
	if(value==0)
		return 0;
	for(i=0;i<6;i++)
	{
		if(!(mask[i]&value))
		{
			ret+=offset;
		}
		else
		{
			value&=mask[i];
		}
		offset/=2;
	}
	return ret+1;	
}

int    Getlowestbit(BYTE  * addr,int size,int bit)
{
	long long test=0;
	int ret=0;
	int i;
	if(size<=0)
		return 0;
	if(size<=8)
	{
		Memcpy(&test,addr,size);	
		if(bit)
			return _get_lowest_bit(test);	
		else
			return _get_lowest_bit(~test);
	}
	for(i=0;i<size;i+=8)
	{
		test=0;
		if(i+8>size)
			Memcpy(&test,addr+i,size-i);
		else
			Memcpy(&test,addr+i,8);
		if(bit)
		{
			if(test==0)
			{
				ret+=64;
				continue;
			}
			return ret+_get_lowest_bit(test);
		}
		else
		{
			if(test==-1)
			{
				ret+=64;
				continue;
			}
			return ret+_get_lowest_bit(~test);
		}
	}
	return 0;
} 

int bitmap_set(char * bitmap, int site)
{
	unsigned char c=1;
	c<<=site%8;
        bitmap[site/8] |=c;
	return 0;
}
int bitmap_clear(char * bitmap, int site)
{
	unsigned char c=1;
	c<<=site%8;
        bitmap[site/8] &=~c;
	return 0;
}

int bitmap_get(char * bitmap,int site)
{
	unsigned char c=1;
	c<<=site%8;
        return bitmap[site/8+1] &c;
}

int bitmap_is_allset(char * bitmap,int size)
{
	unsigned char c=0x7f;

	int i;
	for(i=0;i<size/8;i++)
	{
		if(bitmap[i] !=0xff)
			return 0;
	}
	if(size%8==0)
		return 1;
	c>>=7-size%8;
	if(bitmap[i]!=c)
		return 0;
	return 1;

}

static inline int _isdigit(char c)
{
	if((c>='0') && (c<='9'))
		return 1;
	return 0;
}

static inline int _is_hex_digit(char c)
{
	if(_isdigit(c))
		return c-'0';
	if((c>='a') && (c<='f'))
		return c-'a'+9;
	if((c>='A') && (c<='F'))
		return c-'a'+9;
	return -1;
}

int is_valid_uuid(BYTE * uuid)
{
	int i;
	for(i=0;i<DIGEST_SIZE*2;i++)
	{
		if(_is_hex_digit(uuid[i])>=0)
			continue;
		return 0;
	}
	return 1;
}

static unsigned char iv[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
int sm4_context_crypt( BYTE * input, BYTE ** output, int size,char * passwd)
{
	int i;
	int out_size;
        sm4_context ctx;
	char keypass[DIGEST_SIZE];
	
	BYTE * out_blob;
        if(size<=0)
                return -EINVAL;

	out_size=size;

	out_blob=malloc(out_size);
	if(out_blob==NULL)
		return -ENOMEM;
	memset(keypass,0,DIGEST_SIZE);
	strncpy(keypass,passwd,DIGEST_SIZE);

	sm4_setkey_enc(&ctx,keypass);
	for(i=0;i<=out_size-16;i+=16)
	{
		sm4_crypt_ecb(&ctx,1,16,input+i,out_blob+i);
	}	
	for(;i<out_size;i++)
		out_blob[i]=input[i]^iv[i%16];		
	*output=out_blob;
	return out_size;
}

int sm4_context_decrypt( BYTE * input, BYTE ** output, int size,char * passwd)
{
	int i;
	int out_size;
        sm4_context ctx;
	char keypass[DIGEST_SIZE];
	
	BYTE * out_blob;
        if(size<=0)
                return -EINVAL;

	out_size=size;

	out_blob=malloc(out_size);
	if(out_blob==NULL)
		return -ENOMEM;
	memset(keypass,0,DIGEST_SIZE);
	strncpy(keypass,passwd,DIGEST_SIZE);

	sm4_setkey_dec(&ctx,keypass);
	for(i=0;i<=out_size-16;i+=16)
	{
		sm4_crypt_ecb(&ctx,1,16,input+i,out_blob+i);
	}	
	for(;i<out_size;i++)
		out_blob[i]=input[i]^iv[i%16];		
	*output=out_blob;
	return out_size;
}
