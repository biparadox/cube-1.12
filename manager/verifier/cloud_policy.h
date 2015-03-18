#ifndef LOCAL_FUNC_H
#define LOCAL_FUNC_H

int build_image_mount_respool(int start_no,int end_no,char * name);
void * build_MBR_pcrpolicy(char * dev,char* describe_info);
void * build_filelist_policy(char * mountpoint,char ** filelist,int pcr_index,char * describe_info);
int build_compute_pcrlib(char * dev,char * compute_desc,int trust_level);
int build_image_kernelpcr(char * mountpoint,char * image_desc,int trust_level);
int add_image_kernelpolicy(void * p_pcrs, char * mountpoint,char * image_desc);
int build_image_pcrlib(char * dev,char *mountpoint,char * image_desc,int trust_level);
int build_compute_boot_pcrs(char * dev,char * compute_desc,void ** pcrs);
int build_compute_running_pcrs(char * dev,char * compute_desc,void ** pcrs);
int build_image_boot_pcrs(char * dev,char * mountpoint,char * image_desc, void ** pcrs);
int build_image_running_pcrs(char * dev,char * mountpoint,char * image_desc,void ** pcrs);
int build_entity_policy(char * uuid,void * platform_pcrs,void * boot_pcrs,void * runtime_pcrs,char * policy_describe, void ** entity_policy);
int build_nova_vm_policy(char * uuid,void ** boot_pcrs, void ** running_pcrs,void ** policy);
int build_glance_image_policy(char * uuid,void ** boot_pcrs, void ** running_pcrs,void ** policy);
int build_glance_image_pcrlib(char * uuid,char * desc, int trust_level);

#endif
