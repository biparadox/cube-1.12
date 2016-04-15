/*
 *
 *   Copyright (C) International Business Machines  Corp., 2004, 2005
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include "../../include/tesi.h"
#include "cube_cafunc.h"
#define DIGEST_SIZE 32
#define PADDING_MODE RSA_PKCS1_PADDING

int linux_get_random(void * buf,int num)
{
	int ret=0;
	int fd;
	
	

	fd=open("/dev/random",O_RDONLY);
	if(fd<0)
		return -ENFILE;
	if((num<0)||(num>4096))
		return -EINVAL;
	ret=read(fd,buf,num);
	if(ret<0)
		return -EIO;
	return ret;
}

void * Generate_RSA_Key()
{
	int ret=0;
	RSA	*rsa;
	int 	iBits=1024;
	int	nid=NID_sha1;
	unsigned long e = RSA_F4;
	BIGNUM	*bne;
	unsigned char bData[100]={0};	
	unsigned char bSign[200]={0};
	int iSignlen=sizeof(bSign);	
	int iDatalen=sizeof(bData);	
	
	bne=BN_new();
	ret=BN_set_word(bne,e);
	rsa=RSA_new();
	ret=RSA_generate_key_ex(rsa,2048,bne,NULL);
	if(ret!=1)
	{
		printf("RSA_generate_key_ex err!/n");
		return NULL;
	}
	return rsa;
	
}

int Sign_RSA_file(char * filename, void * rsa_data,char * signfile)
{
	int ret;
	int fd;
	char SignData[256];
	int blob_size;
	struct stat file_stat;
	char *buffer;
	int  signlen;
	RSA * rsa=(RSA *)rsa_data;

	fd=open(filename,O_RDONLY);
	if(fd<=0)
		return -EINVAL;
	ret = fstat(fd,&file_stat);
	if(ret<0)
	{
		return -EACCES;
	}

	buffer=malloc(file_stat.st_size);
	if(buffer==NULL)
		return -ENOMEM;
	ret=read(fd,buffer,file_stat.st_size);
	if(ret!=file_stat.st_size)
		return -EINVAL;
	close(fd);
	ret=RSA_sign(NID_sha1,buffer,ret,SignData,&signlen,rsa);
	if(ret!=1)
		return -EINVAL;
	free(buffer);
	fd=open(signfile,O_WRONLY|O_CREAT|O_TRUNC);
	if(fd<0)
		return -EINVAL;
	
	ret=write(fd,SignData,signlen);
	if(ret!=signlen)
		return -EINVAL;
	close(fd);
	return TSS_SUCCESS;
}

int Pubcrypt_RSA_file(char * filename, void * rsa_data,char * cipherfile)
{
	int ret;
	int fd;
	int blob_size;
	struct stat file_stat;
	char *plain_buf;
	char * cipher_buf;
	int  plainlen;
	int  cipherlen;
	const int tailsize=256;
	RSA * rsa=(RSA *)rsa_data;

	fd=open(filename,O_RDONLY);
	if(fd<=0)
		return -EINVAL;
	ret = fstat(fd,&file_stat);
	if(ret<0)
	{
		return -EACCES;
	}

	plain_buf=malloc(file_stat.st_size);
	if(plain_buf==NULL)
		return -ENOMEM;
	plainlen=read(fd,plain_buf,file_stat.st_size);
	if(plainlen!=file_stat.st_size)
		return -EINVAL;
	close(fd);

	cipher_buf=malloc(plainlen+tailsize);
	if(cipher_buf==NULL)
		return -ENOMEM;

	cipherlen=RSA_public_encrypt(plainlen,plain_buf,cipher_buf,rsa,PADDING_MODE);
	if(cipherlen<0)
		return -EINVAL;
	free(plain_buf);
	fd=open(cipherfile,O_WRONLY|O_CREAT|O_TRUNC);
	if(fd<0)
		return -EINVAL;
	
	ret=write(fd,cipher_buf,cipherlen);
	if(ret!=cipherlen)
		return -EINVAL;
	close(fd);
	return TSS_SUCCESS;
}

int Privdecrypt_RSA_file(char * filename, void * rsa_data,char * plainfile)
{
	int ret;
	int fd;
	int blob_size;
	struct stat file_stat;
	char *plain_buf;
	char * cipher_buf;
	int  plainlen;
	int  cipherlen;
	const int tailsize=256;
	RSA * rsa=(RSA *)rsa_data;

	fd=open(filename,O_RDONLY);
	if(fd<=0)
		return -EINVAL;
	ret = fstat(fd,&file_stat);
	if(ret<0)
	{
		return -EACCES;
	}

	cipher_buf=malloc(file_stat.st_size);
	if(cipher_buf==NULL)
		return -ENOMEM;
	cipherlen=read(fd,cipher_buf,file_stat.st_size);
	if(cipherlen!=file_stat.st_size)
		return -EINVAL;
	close(fd);

	plain_buf=malloc(cipherlen);
	if(plain_buf==NULL)
		return -ENOMEM;

	plainlen=RSA_private_decrypt(cipherlen,cipher_buf,plain_buf,rsa,PADDING_MODE);
	if(plainlen<0)
		return -EINVAL;
	free(cipher_buf);
	fd=open(plainfile,O_WRONLY|O_CREAT|O_TRUNC);
	if(fd<0)
		return -EINVAL;
	
	ret=write(fd,plain_buf,plainlen);
	if(ret!=plainlen)
		return -EINVAL;
	close(fd);
	return TSS_SUCCESS;
}

int Verify_RSA_file(char * filename, void * rsa_data,char * signfile)
{
	int ret;
	int fd;
	char SignData[256];
	int blob_size;
	struct stat file_stat;
	char *buffer;
	int  signlen;
	int  datalen;
	RSA * rsa=(RSA *)rsa_data;

	fd=open(filename,O_RDONLY);
	if(fd<=0)
		return -EINVAL;
	ret = fstat(fd,&file_stat);
	if(ret<0)
	{
		return -EACCES;
	}

	buffer=malloc(file_stat.st_size);
	if(buffer==NULL)
		return -ENOMEM;
	datalen=read(fd,buffer,file_stat.st_size);
	if(datalen!=file_stat.st_size)
		return -EINVAL;
	close(fd);

	fd=open(signfile,O_RDONLY);
	if(fd<0)
		return -EINVAL;

	ret = fstat(fd,&file_stat);
	if(ret<0)
	{
		return -EACCES;
	}

	if(file_stat.st_size>256)
		return -EINVAL;

	
	signlen=read(fd,SignData,file_stat.st_size);
	if(signlen<0)
		return -EINVAL;
	close(fd);

	ret=RSA_verify(NID_sha1,buffer,datalen,SignData,signlen,rsa);
	if(ret!=1)
		return -EINVAL;
	free(buffer);
	return TSS_SUCCESS;
}

#define ENTRY_COUNT 6

struct entry entries[ENTRY_COUNT] =
{
	{"countryName","CN"},
	{"stateOrProvinceName","BeiJing"},
	{"localityName","Chaoyang"},
	{"organizationName","bjut.edu.cn"},
	{"organizationalUnitName","CS Academy"},
	{"commonName","Test CA"},
};

int print_openssl_err()
{
	char errstring[120];
	int err=ERR_get_error();
	
	ERR_error_string(ERR_get_error(),errstring);
        printf("openssl %s\n",errstring);
	return err;
};

int main( void )
{
	int ret;
	char			*function = "Tspi_TESI_Init";
	TSS_RESULT		result = 0;
	TSS_HKEY 		hCAKey;
	TSS_HKEY 		hSignKey;
	TSS_HKEY 		hReloadKey;
	TSS_HKEY 		hReloadPubKey;

	X509_REQ * cert_req;
	X509 * cert;
	
	char uuid[DIGEST_SIZE*2];
	char buf[4096];

	RSA * rsa;
	RSA * rsa1;
	RSA * rsa2;


	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	result=TESI_Local_ReloadWithAuth("ooo","sss");

	if ( result != TSS_SUCCESS )
	{
		printf("TESI_Local_Load Err!\n");
		return result;
	}

	int num=1024;
	result=TESI_Local_GetRandom(buf,num);
	if(result == TSS_SUCCESS)
		printf("Get %d Random num SUCCEED!\n",num);
	else
		return -EINVAL;
	
	RAND_seed(buf,num);
	
	rsa=Generate_RSA_Key();
	if(rsa==NULL)
	{
		printf("Generate RSA Key Failed!\n");
		return -EINVAL;
	}

	ret=Sign_RSA_file("hello.txt",rsa,"hello.sig");
	ret=Pubcrypt_RSA_file("hello.txt",rsa,"hello.crypt");

	WritePrivKey(rsa,"CA",password);
	WritePubKey(rsa,"CA");

	
	
//	RSA_free(rsa);

	result=ReadPubKey(&rsa1,"CA");
	if(result == TSS_SUCCESS)
		printf("read pubKey SUCCEED!\n");
	else
		return -EINVAL;
	
	result=Verify_RSA_file("hello.txt",rsa1,"hello.sig");

	if(result==TSS_SUCCESS)
	{
		printf("verify file succeed!\n");
	}
	else
	{
		printf("Verify file failed!\n");
	} 

//	RSA_free(rsa1);
	result=ReadPrivKey(&rsa2,"CA",password);
	if(result == TSS_SUCCESS)
		printf("read privkey  SUCCEED!\n");
	else
		return -EINVAL;
	ret=Privdecrypt_RSA_file("hello.crypt",rsa2,"hello1.txt");


	cert_req=X509_REQ_new();
	if(cert_req==NULL)
		return -ENOMEM;
	X509_REQ_set_version(cert_req,2L);
	
	X509_NAME * subject;
	subject=X509_NAME_new();
	if(subject==NULL)
	{
		printf("create X509 NAME error!\n");
	}
	int i;
	for(i=0;i <ENTRY_COUNT;i++)
	{
		int nid;
		X509_NAME_ENTRY *ent;
		if((nid = OBJ_txt2nid(entries[i].key)) == NID_undef)
		{
			printf("error finding NID for %s\n",entries[i].key);
			return -EINVAL;
		}
		if(!(ent=X509_NAME_ENTRY_create_by_NID(NULL,nid,MBSTRING_ASC,entries[i].value,-1)))
		{
			printf("error creating Name %s entrys %s \n",entries[i].key,entries[i].value);
			return -EINVAL;
		}
		ret=X509_NAME_add_entry(subject,ent,-1,0);
		if(ret!=1)
			return -EINVAL;
	}
	ret=X509_REQ_set_subject_name(cert_req,subject);
	if(ret!=1)
		return -EINVAL;
	EVP_PKEY * pubkey = EVP_PKEY_new();
	EVP_PKEY * privkey = EVP_PKEY_new();
	if(pubkey==NULL)
	{
		ret=print_openssl_err();
		return -EINVAL;
	}
	
	ret=EVP_PKEY_set1_RSA(pubkey,rsa1);
	if(ret!=1)
	{
		ret=print_openssl_err();
		return -EINVAL;
	}
	
	ret=X509_REQ_set_pubkey(cert_req,pubkey);
	if(ret!=1)
	{
		ret=print_openssl_err();
		return -EINVAL;
	}
	
	ret=EVP_PKEY_set1_RSA(privkey,rsa2);
	if(ret!=1)
	{
		ret=print_openssl_err();
		return -EINVAL;
	}
	
	ret=X509_REQ_sign(cert_req,privkey,EVP_sha1());
	if(ret<0)
	{
		ret=print_openssl_err();
		return -EINVAL;
	}
	
	FILE * fp;
	if(!(fp=fopen("CA.req","w")))
	{
		printf( "open req file error!\n");
		return -EIO;
	}
	if(PEM_write_X509_REQ(fp,cert_req) != 1)
	{
		ret=print_openssl_err();
		return -EINVAL;
	}
	fclose(fp);

	cert=X509_REQ_to_X509(cert_req,7320,privkey);
	if(cert==NULL)
	{
		ret=print_openssl_err();
		return -EINVAL;
	}	

	if(!(fp=fopen("CA.crt","w")))
	{
		printf( "open cert file error!\n");
		return -EIO;
	}
	if(PEM_write_X509(fp,cert) != 1)
	{
		ret=print_openssl_err();
		return -EINVAL;
	}
	fclose(fp);

	X509_REQ_free(cert_req);
	X509_free(cert);

	return 0;

/*
	TESI_Local_GetPubEKWithUUID(uuid,"ooo");
	TESI_Local_GetPubEK("pubek","ooo");

	result=TESI_Local_GetPubKeyFromCA(&hCAKey,"CA");


	result=TESI_Local_CreateSignKey(&hSignKey,(TSS_HKEY)NULL,"sss","kkk");
	if(result == TSS_SUCCESS)
		printf("Create SignKey SUCCEED!\n");

	TESI_Local_WriteKeyBlob(hSignKey,"localsignkey");
	TESI_Local_WritePubKey(hSignKey,"localsignkey");
	
	TESI_Local_ReadKeyBlob(&hReloadKey,"localsignkey");
	TESI_Local_SignFile("test.txt",hReloadKey,"testsign","kkk");
	TESI_Local_ReadPubKey(&hReloadPubKey,"localsignkey");
	TESI_Local_VerifyFile("test.txt",hReloadPubKey,"testsign");

	TESI_Local_Fin();
*/
	return result;
}
