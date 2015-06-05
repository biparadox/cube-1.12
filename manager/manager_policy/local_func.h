#ifndef LOCAL_FUNC_H
#define LOCAL_FUNC_H

struct userhostvm_info
{
       char uuid[DIGEST_SIZE*2];
       char platform_uuid[DIGEST_SIZE*2];
       char *vmname;
       char *hostname;
       char *username;
}__attribute__((packed));

static struct struct_elem_attr userhostvminfo_desc[] =
{
    {"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
    {"platform_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
    {"vmname",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
    {"hostname",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
    {"username",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL}
};
void * build_glance_image_policy(char * uuid);

#endif
