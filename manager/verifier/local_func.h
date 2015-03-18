#ifndef LOCAL_FUNC_H
#define LOCAL_FUNC_H

void ** create_verify_list(char * policy_type,char * entity_uuid,int list_num);
int verify_pcrs_set(void * v_pcrs,void * v_list);

#endif
