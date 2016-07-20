#ifndef _LABEL_COMPARE_H
#define _LABEL_COMPARE_H

int label_user_comp_euserid(struct list_head * head, int uid);
int label_userid_comp_userid(struct list_head * head, int uid);
int label_authuser_typecomp(int findtype,struct list_head * head, char * name);
int label_obj_comp_markpolicy(struct list_head * head, char * policyname);
int label_obj_comp_name(struct list_head * head, char * name);
int label_obj_typecomp_name(int findtype,struct list_head * head, char * name);
int label_obj_comp_uniname(struct list_head * head, char * name);
int label_obj_comp_elem(struct list_head * head, struct list_head * elem);
int label_obj_match_name(struct list_head * head, char * name);
int label_obj_match_elem(struct list_head * head, struct list_head * elem);
int label_user_comp_name(struct list_head * head, char * name);
int os210_comp_namepath(char *path1, char *path2);

int label_proc_comp_uniname(struct list_head * head, char * name);//7.18
int label_proc_comp_name(struct list_head * head, char * name);//7.18

int label_sub_comp_name(struct list_head * head, void * name);
int label_sub_comp_group(struct list_head * head, char * groupname);
int label_dac_comp_record(struct list_head * head, DAC_POLICY * dacrecord);
int label_dac_comp_match(struct list_head * head, void * dacrecord);
int label_priv_comp_record(struct list_head * head, 
	PRIV_POLICY * privrecord);
int label_priv_comp_match(struct list_head * head, void * privrecord);
char * label_get_tailname(char * name);
char * label_get_dirname(char * name);
int label_sub_comp_label(struct list_head * head, void * label);
int label_obj_comp_label(struct list_head * head, void * label);
int label_user_comp_label(struct list_head * head, void * label);
#endif
