#ifndef  LOCAL_EXPAND_DEFINE_H
#define  LOCAL_EXPAND_DEFINE_H

struct  expand_data_conn
{
	int data_size;
	char tag[4];		//should be "CONE"
	char conn_uuid[DIGEST_SIZE*2];
	char *conn_name;	
	char *conn_proc;	
	int  conn_type;
	int  conn_state;
}__attribute__((packed));

static struct struct_elem_attr expand_data_conn_desc[]=
{
	{"data_size",OS210_TYPE_INT,sizeof(int),0},
	{"tag",OS210_TYPE_STRING,4,0},
	{"conn_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"conn_name",OS210_TYPE_ESTRING,DIGEST_SIZE*2,NULL},
	{"conn_proc",OS210_TYPE_ESTRING,DIGEST_SIZE*2,NULL},
	{"conn_type",OS210_TYPE_ENUM,sizeof(int),connector_type_valuelist},
	{"conn_state",OS210_TYPE_ENUM,sizeof(int),connector_state_valuelist},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

struct  expand_route_conn
{
	int data_size;
	char tag[4];		//should be "ROUE"
	char conn_uuid[DIGEST_SIZE*2];
	char *conn_name;	
	int  skip_num;
}__attribute__((packed));

static struct struct_elem_attr expand_route_conn_desc[]=
{
	{"data_size",OS210_TYPE_INT,sizeof(int),0},
	{"tag",OS210_TYPE_STRING,4,0},
	{"conn_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"conn_name",OS210_TYPE_ESTRING,DIGEST_SIZE*2,NULL},
	{"skip_num",OS210_TYPE_INT,sizeof(int),0},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

#endif
