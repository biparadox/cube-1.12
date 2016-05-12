#include <stdlib.h>
#include <string.h>

#include "../include/data_type.h"
#include "../include/struct_deal.h"
#include "../include/extern_struct.h"
#include "../include/extern_struct_desc.h"
#include "../logic_baselib.h"
#include "vtpm_struct.h"
#include "vtpm_desc.h"
//#include "logic_vtpm.h"


int main()
{
	
	int i;
	char * policy_package;
	int retval;

	struct vTPM_wrappedkey * wrappedkey;
	void * policy;
	logic_baselib_init();

	register_policy_lib("BLBK",wrappedkey_desc,&wrappedkey_lib_ops);
	retval=LoadPolicyFromFile("wrappedkey.lib","BLBK");

	policy=GetFirstPolicy("BLBK");
	i=0;
	while(policy!=NULL)
	{
		OutPutPolicy(policy,"BLBK");
		printf("\n");
		wrappedkey=(struct vTPM_wrappedkey *)policy;
		policy=GetNextPolicy("BLBK");
		i++;
	}	

	return 0;
}

