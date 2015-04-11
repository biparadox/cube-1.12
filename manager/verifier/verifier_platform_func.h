#ifndef VERIFIER_IMAGE_FUNC_H
#define VERIFIER_IMAGE_FUNC_H

// init function
int verifier_platform_init(void * proc,void * para);
int verifier_platform_start(void * proc,void * para);
int proc_keep_pcrpolicy(void * sub_proc,void * message);
#endif
