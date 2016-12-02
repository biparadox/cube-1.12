#ifndef ROUTER_STRUCT_H
#define ROUTER_STRUCT_H

static struct struct_elem_attr message_policy_desc[] =
{
    {"name",OS210_TYPE_ESTRING,DIGEST_SIZE,NULL},
    {"type",OS210_TYPE_ENUM,sizeof(int),&message_flow_valuelist},
    {"flag",OS210_TYPE_FLAG,sizeof(int),&message_flag_valuelist},
    {"sender_proc",OS210_TYPE_ESTRING,DIGEST_SIZE,NULL},
    {"jump",OS210_TYPE_INT,sizeof(int),NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};


static struct struct_elem_attr match_rule_desc[] =
{
    {"op",OS210_TYPE_ENUM,sizeof(int),&match_rule_op_valuelist},
    {"area",OS210_TYPE_ENUM,sizeof(int),&message_area_valuelist},
    {"expand_type",OS210_TYPE_STRING,4,NULL},
    {"seg",OS210_TYPE_ESTRING,DIGEST_SIZE*2,NULL},
    {"value",OS210_TYPE_ESTRING,1024,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr router_rule_desc[] =
{
    {"type",OS210_TYPE_FLAG,sizeof(int),&message_flow_valuelist},
    {"state",OS210_TYPE_ENUM,sizeof(int),&message_flow_valuelist},
    {"target_type",OS210_TYPE_ENUM,sizeof(int),&message_target_type_valuelist},
    {"define_area",OS210_TYPE_ENUM,sizeof(int),&message_area_valuelist},
    {"target_expand",OS210_TYPE_STRING,4,NULL},
    {"target_name",OS210_TYPE_ESTRING,DIGEST_SIZE*2,NULL},
    {NULL,OS210_TYPE_ENDDATA,0,NULL}
};

struct expand_flow_trace
{
    int  data_size;
    char tag[4];                 // this should be "FTRE" and "APRE"
    int  record_num;
    char *trace_record;
} __attribute__((packed));

struct expand_aspect_point
{
    int  data_size;
    char tag[4];                 // this should be "APRE"
    int  record_num;
    char * aspect_proc;
    char * aspect_point;
} __attribute__((packed));

struct expand_route_record
{
	int data_size;
	char tag[4];
	char sender_uuid[DIGEST_SIZE*2];
	char receiver_uuid[DIGEST_SIZE*2];
	char route[DIGEST_SIZE];
	int  flow;
	int  state;
	int  flag;
	int  ljump;
	int  rjump;	
} __attribute__((packed));


static struct struct_elem_attr expand_flow_trace_desc[] =
{
    {"data_size",OS210_TYPE_INT,sizeof(int),0},
    {"tag",OS210_TYPE_STRING,4,0},
    {"record_num",OS210_TYPE_INT,sizeof(int),0},
    {"trace_record",OS210_TYPE_DEFSTRARRAY,DIGEST_SIZE*2,"record_num"},
    {NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr expand_aspect_point_desc[] =
{
    {"data_size",OS210_TYPE_INT,sizeof(int),0},
    {"tag",OS210_TYPE_STRING,4,0},
    {"record_num",OS210_TYPE_INT,sizeof(int),0},
    {"aspect_proc",OS210_TYPE_DEFSTRARRAY,DIGEST_SIZE*2,"record_num"},
    {"aspect_point",OS210_TYPE_DEFSTRARRAY,DIGEST_SIZE*2,"record_num"},
    {NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr router_record_desc[]=   // record type: "ROUE"
{
    	{"data_size",OS210_TYPE_INT,sizeof(int),0},
    	{"tag",OS210_TYPE_STRING,4,0},
	{"sender_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"receiver_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"route",OS210_TYPE_STRING,DIGEST_SIZE,NULL},
	{"flow",OS210_TYPE_FLAG,sizeof(UINT32),&message_flow_valuelist},
	{"state",OS210_TYPE_ENUM,sizeof(UINT32),&message_flow_valuelist},
	{"flag",OS210_TYPE_FLAG,sizeof(UINT32),&message_flag_valuelist},
	{"ljump",OS210_TYPE_INT,sizeof(UINT32),NULL},
	{"rjump",OS210_TYPE_INT,sizeof(UINT32),NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
#endif // ROUTER_STRUCT_H
