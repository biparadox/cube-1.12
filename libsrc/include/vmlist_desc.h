#ifndef VMLIST_DESC_H
#define VMLIST_DESC_H
#include "../include/data_type.h"
#include "../include/struct_deal.h"

static struct struct_elem_attr vminfo_os_desc[] =
{
	{"type",OS210_TYPE_ESTRING,256,NULL},
	{"bootdev",OS210_TYPE_ESTRING,256,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr vminfo_diskinfo_desc[] =
{
	{"name",OS210_TYPE_ESTRING,256,NULL},
	{"type",OS210_TYPE_ESTRING,256,NULL},
	{"cache",OS210_TYPE_ESTRING,256,NULL},
	{"sourcefile",OS210_TYPE_ESTRING,256,NULL},
	{"bus",OS210_TYPE_ESTRING,256,NULL},
	{"dev",OS210_TYPE_ESTRING,256,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr vminfo_network_desc[] =
{
	{"interfacetype",OS210_TYPE_ESTRING,256,NULL},
	{"macadd",OS210_TYPE_ESTRING,256,NULL},
	{"model",OS210_TYPE_ESTRING,256,NULL},
	{"bridge",OS210_TYPE_ESTRING,256,NULL},
	{"dev",OS210_TYPE_ESTRING,256,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr vminfo_desc[] =
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"platform_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"hostname",OS210_TYPE_ESTRING,256,NULL},
	{"host",OS210_TYPE_ESTRING,256,NULL},
	{"owner",OS210_TYPE_ESTRING,256,NULL},
	{"memory",OS210_TYPE_LONGLONG,8,NULL},
	{"vcpu",OS210_TYPE_INT,4,NULL},
	{"os",OS210_TYPE_ORGCHAIN,0,vminfo_os_desc},
	{"diskinfo",OS210_TYPE_ORGCHAIN,0,vminfo_diskinfo_desc},
	{"network",OS210_TYPE_ORGCHAIN,0,vminfo_network_desc},
	{"filepath",OS210_TYPE_ESTRING,256,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr image_info_desc[]=
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"image_name",OS210_TYPE_ESTRING,256,NULL},
	{"image_size",OS210_TYPE_LONGLONG,8,NULL},
	{"image_disk_format",OS210_TYPE_ESTRING,256,NULL},
	{"image_checksum",OS210_TYPE_ESTRING,256,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr openstack_user_desc[]=
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"name",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"project_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr openstack_project_desc[]=
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"name",OS210_TYPE_ESTRING,256,NULL},
	{"owner_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"user_num",OS210_TYPE_INT,sizeof(int),NULL},
	{"user_uuid",OS210_TYPE_DEFSTRARRAY,DIGEST_SIZE*2,"user_num"},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr platform_info_desc[]=
{
        {"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
        {"name",OS210_TYPE_ESTRING,1024,NULL},
        {"tpm_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
        {"state",OS210_TYPE_INT,sizeof(int),NULL},
        {"boot_loader",OS210_TYPE_ESTRING,1024,NULL},
        {"kernel",OS210_TYPE_ESTRING,1024,NULL},
        {"hypervisor",OS210_TYPE_ESTRING,1024,NULL},
        {"hype_ver",OS210_TYPE_ESTRING,1024,NULL},

	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
#endif
