#ifndef LOCAL_FUNC_H
#define LOCAL_FUNC_H

int get_image_from_dbres(void * image_info, void * res);
int get_user_from_dbres(void * user_info, void * res);
int get_platform_from_dbres(void * platform_info, void * res);
int get_vm_from_dbres(void * vm_info, void * db_res,void * sql_connection);

#endif
