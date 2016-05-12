
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

struct info
{
	
	char * uuid;
	long  memory;
	int vcpu;
	struct os os;
	struct diskinfo diskinfo;
	struct network network;
	char * filepath;
} __attribute__((packed));  
