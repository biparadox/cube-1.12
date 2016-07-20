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

int manager_policy_init()
{
	int ret;
	return 0;
}

int vm_info_memdb_init(void * sub_proc,void * para)
{
	int retval;
	char * record_package;

	return 0;
}

int image_info_memdb_init(void * sub_proc,void * para)
{
	int retval;
	char * record_package;

	return 0;
}

int platform_info_memdb_init(void * sub_proc,void * para)
{
	int retval;
	char * record_package;

	return 0;
}

int vm_policy_memdb_init(void * sub_proc,void * para)
{
	int retval;
	char * record_package;

	return 0;
}
int image_policy_memdb_init(void * sub_proc,void * para)
{
	int retval;
	char * record_package;

	return 0;
}
int platform_policy_memdb_init(void * sub_proc,void * para)
{
	int retval;
	char * record_package;

	return 0;
}


int pcr_policy_memdb_init()
{
	int retval;
	char * record_package;

	return 0;
}

int policy_file_memdb_init()
{
	int retval;
	char * record_package;

	return 0;
}
