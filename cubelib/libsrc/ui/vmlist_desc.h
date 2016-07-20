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
	{"uuid",OS210_TYPE_ESTRING,80,NULL},
	{"memory",OS210_TYPE_LONGLONG,8,NULL},
	{"vcpu",OS210_TYPE_INT,4,NULL},
	{"os",OS210_TYPE_ORGCHAIN,0,vminfo_os_desc},
	{"diskinfo",OS210_TYPE_ORGCHAIN,0,vminfo_diskinfo_desc},
	{"network",OS210_TYPE_ORGCHAIN,0,vminfo_network_desc},
	{"filepath",OS210_TYPE_ESTRING,256,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
