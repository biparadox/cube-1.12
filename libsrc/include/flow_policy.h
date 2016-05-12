#ifndef FLOW_POLICY_H
#define FLOW_POLICY_H

#define DIGEST_SIZE 32

int read_flow_cfg(void * proc,FILE * stream);
int flow_tube_init(void ** tubelist);
int flow_tube_getfirst(void * tubelist,void ** tube);
int flow_tube_getnext(void * tubelist,void ** tube);
//int flow_tube_find(char * proc_name,void ** tube);
int flow_tube_add(void * tubelist,void * tube);
//int flow_tube_del(void * tube);
int flow_tube_reset(void * tubelist);


int flow_tube_getsenderproc(void * tube,char ** proc_name);
int flow_tube_getreceiverproc(void * tube,char ** proc_name);

int tube_policy_init(void * tubelist,void ** tube);
int tube_policy_add(void * tube ,void * policy);
int tube_policy_reset(void * tube);
int tube_policy_getfirst(void * tube,void ** policy);
int tube_policy_getnext(void * tube,void ** policy);
/*
int entity_list_create(char * proc_name,void ** entity_list);  // alloc an entity list to let main proc put entity's value in it
int entity_list_addentity(void * entity_list,void * entity);
void entity_list_destroy(void * entity_list);
*/
int flow_policy_entitytype(void * policy);   // get this policy's entity type
int flow_policy_optype(void * policy);   // get this policy's operation type
//int tube_policy_getnext(char * proc_name,void ** policy);

int match_flow_policy(void * proc,void * entity,void * para);
int flow_tube_match(void * tube,void * entity_list);       // match policy with finished entity list 
int is_policy_need_entity(void * policy);


enum dispatch_policy_type
{
	DISPATCH_POLICY_TYPE_AND=0x01,
	DISPATCH_POLICY_TYPE_OR=0x02,
	DISPATCH_POLICY_TYPE_EXCEPT=0x04,
	DISPATCH_POLICY_TYPE_LBRACE=0x08,
	DISPATCH_POLICY_TYPE_RBRACE=0x10,
	DISPATCH_POLICY_TYPE_LROUND=0x20,
	DISPATCH_POLICY_TYPE_RROUND=0x40,
};

enum dispatch_target_type
{
	DISPATCH_TARGET_LOCAL,
	DISPATCH_TARGET_SERVER,
	DISPATCH_TARGET_ENDPOINT,
	DISPATCH_TARGET_REPLY,
	DISPATCH_TARGET_AUDIT,
	DISPATCH_TARGET_EXCEPT,
	DISPATCH_TARGET_NULL,
};


static inline int is_policy_type_logicop(int policy_type)
{
	int opmask= DISPATCH_POLICY_TYPE_AND | DISPATCH_POLICY_TYPE_OR |
			DISPATCH_POLICY_TYPE_EXCEPT;

	int nopmask= DISPATCH_POLICY_TYPE_LBRACE | DISPATCH_POLICY_TYPE_RBRACE |
			DISPATCH_POLICY_TYPE_LROUND | DISPATCH_POLICY_TYPE_RROUND;

	if(policy_type & nopmask)   // there is a nop (\(,\),\{,\}) in policy_type
		return 0;
	if(policy_type & (~opmask))  // there is some extra  bit in policy_type
		return -EINVAL;
	return 1;
};



enum dispatch_match_entity
{
	DISPATCH_MATCH_MSG=0x10,
	DISPATCH_MATCH_MSG_RECORD=0x20,
	DISPATCH_MATCH_MSG_EXPAND=0x40,
	DISPATCH_MATCH_PROC=0x100,
};

typedef struct json_element
{
	char * name;
	char * value;
}JSON_ELEMENT;

typedef struct dispatch_tube_policy
{
	int  policy_type;
	int  match_entity;
	char type[4];
	int  matchelemnum;
	char **matchelem;	
	void * entity;
}__attribute__((packed)) DISPATCH_TUBE_POLICY;


typedef struct dispatch_tube_para
{
	char sender_proc[DIGEST_SIZE*2];
	char receiver_proc[DIGEST_SIZE*2];
	char callback[DIGEST_SIZE*2];
	int  tube_no;
	void * policy_list;
	void * curr;
}__attribute__((packed)) DISPATCH_TUBE;



typedef struct dispatch_deal_para
{
	char deal_func[DIGEST_SIZE*2];
	void * policy_list;
	void * curr;
}DISPATCH_DEAL;



#endif // PROC_CONFIG_H
