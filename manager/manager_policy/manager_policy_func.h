#ifndef MANAGER_POLICY_FUNC_H
#define MANAGER_POLICY_FUNC_H

static struct struct_elem_attr share_data_desc[]=
{
	{"username",OS210_TYPE_ESTRING,80,NULL},
	{"userpass",OS210_TYPE_ESTRING,80,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

int manager_policy_init(void * proc);
int connector_init(void * proc,void * para,void ** pointer);
int connector_msgdeal(void * para);


int vm_info_memdb_init();
int image_info_memdb_init();
int vm_policy_memdb_init();
int pcr_policy_memdb_init();
int policy_file_memdb_init();
int process_monitor_message(char * data, int size,void * trust_conn);
int process_trust_message(char *data,int size, void * conn);
int process_interface_cmd(void * message, void * interface_conn, void * verifier_conn,void * trust_conn);

struct image_policy_object
{
	struct image_info * image;
	struct vm_policy * image_policy;
	TESI_SIGN_DATA * signdata;
	struct tcloud_connector * conn;
};
struct vm_policy_object
{
	struct vm_info * vm;
	struct vm_policy * vm_policy;
	TESI_SIGN_DATA * signdata;
	struct tcloud_connector * conn;
};

#endif
