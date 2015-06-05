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

int get_image_from_dbres(void * image_info, void * res);
int get_user_from_dbres(void * user_info, void * res);
int get_platform_from_dbres(void * platform_info, void * res);
int get_vm_from_dbres(void * vm_info, void * db_res,void * sql_connection);

#endif
