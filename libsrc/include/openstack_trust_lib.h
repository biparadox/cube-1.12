#ifndef OPENSTACK_TRUST_LIB_H
#define OPENSTACK_TRUST_LIB_H
int read_message_from_conn(void ** message,void * conn);
//void * read_message_from_conn(void * conn);
int receive_local_client_ack(void * message_box,void * conn);
int trust_server_login(char * user,char * passwd,void * conn);
void * process_return_cmd(void * message);
int build_filedata_struct(void * *pfdata,char * filename);
int get_filedata_from_message(void * message);
int message_forward(void * message, void * conn);
int message_send(void * message, void * conn);
int openstack_trust_lib_init();

int proc_share_data_init(struct struct_elem_attr * share_data_desc);
int proc_share_data_getstate();
int proc_share_data_setstate(int state);
void * proc_share_data_getpointer();
int proc_share_data_setpointer(void * pointer);
int proc_share_data_getvalue(char * valuename,void * value);
int  proc_share_data_setvalue(char * valuename,void * value);
int proc_share_data_reset();
int proc_share_data_destroy();

int create_internal_return_message(int retval,void ** msg);
int get_channel_extern_uuid(void * channel,BYTE * uuid);
int set_channel_extern_uuid(void * channel,BYTE * uuid);
int get_channel_extern_state(void * channel);
int set_channel_extern_state(void * channel,int state);

void * get_record_from_message(void * message_box);

enum base_channel_state
{
	PROC_CHANNEL_INIT=0,
	PROC_CHANNEL_RESET,
	PROC_CHANNEL_SENDSYN,
	PROC_CHANNEL_RECVACK,
	PROC_CHANNEL_READY,
};
int find_conn_with_expand(void * hub,void * expand,void ** conn);
#endif
