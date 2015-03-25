#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

#include "../include/data_type.h"
#include "../include/struct_deal.h"
#include "../include/extern_defno.h"
#include "../include/extern_struct.h"
#include "../include/sysfunc.h"
#include "../include/message_struct.h"
#include "../include/connector.h"
#include "../include/logic_baselib.h"
#include "../include/policy_ui.h"
#include "../include/vm_policy.h"
#include "../include/vmlist.h"
#include "../include/vtpm_struct.h"
#include "../include/sec_entity.h"
#include "../include/openstack_trust_lib.h"
#include "../include/main_proc_init.h"

#include "cloud_config.h"
#include "main_proc_func.h"
#include "proc_config.h"


struct main_proc_pointer
{
	void * pointer;
};
int verifier_init(void * proc,void * para)
{
	int ret;
	char local_uuid[DIGEST_SIZE*2];
	
	struct main_proc_pointer * main_pointer;
//	main_pointer= kmalloc(sizeof(struct main_proc_pointer),GFP_KERNEL);
	main_pointer= malloc(sizeof(struct main_proc_pointer));
	if(main_pointer==NULL)
		return -ENOMEM;
        ret=get_local_uuid(local_uuid);
        printf("this machine's local uuid is %s\n",local_uuid);
	proc_share_data_setvalue("local_uuid",local_uuid);
	proc_share_data_setvalue("proc_name",para);
	proc_share_data_setpointer(main_pointer);
	sec_subject_register_statelist(proc,main_state_list);
	return 0;
}
int image_policy_memdb_init()
{
	int retval;
	char *image_dirname="image";
	return 0;
}
int platform_policy_memdb_init()
{
	return 0;
}
int vm_policy_memdb_init()
{
	return 0;
}



#define MBR_PCR_INDEX  4
#define KERNEL_PCR_INDEX  10
#define SECURE_PCR_INDEX  11

int pcr_policy_memdb_init()
{
	return 0;
}
int pcr_info_memdb_init()
{
	return 0;
}
int file_policy_memdb_init()
{
	return 0;
}
