#ifndef VMLIST_H
#define VMLIST_H

struct image_info
{
	char uuid[DIGEST_SIZE*2];
	char *image_name;
	long image_size;
	char *image_disk_format;
	char *image_checksum;
}__attribute__((packed));
struct os
{
	char * type;
	char * bootdev;
} __attribute__((packed));  

struct diskinfo
{
	char * name;
	char * type;
	char * cache;
	char * sourcefile;
	char * bus;
	char * dev;
} __attribute__((packed));  

struct network 
{
	char * interfacetype;
	char * macadd;
	char * model;
	char * bridge;
	char * dev;
} __attribute__((packed));  

struct vm_info
{
	
	char uuid[DIGEST_SIZE*2];
	char platform_uuid[DIGEST_SIZE*2];
	char * hostname;
	char * host;
	char * owner;
	long long memory;
	int vcpu;
	struct os os;
	struct diskinfo diskinfo;
	struct network network;
	char * filepath;
} __attribute__((packed));  

struct openstack_user
{
   char uuid[DIGEST_SIZE*2];
   char name[DIGEST_SIZE*2];
   char project_uuid[DIGEST_SIZE*2];
};

struct openstack_project
{
	char uuid[DIGEST_SIZE*2];
	char * name;
	char owner_uuid[DIGEST_SIZE*2];
	int  user_num;
	char * * user_uuid;
};

struct platform_info
{
	char uuid[DIGEST_SIZE*2];
	char * name;
	char tpm_uuid[DIGEST_SIZE*2];
	int  state;
	char * boot_loader;
	char * kernel;
	char * hypervisor;
	char * hype_ver;
}__attribute__((packed));
#endif
