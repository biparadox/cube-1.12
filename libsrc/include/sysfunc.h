#ifndef  LOGICCUBE_SYSFUNC_H
#define  LOGICCUBE_SYSFUNC_H

int get_local_uuid(char * uuid);
int mount_image(char * imagepath,char * device,char *mountpoint);
int umount_image(char * device,char *mountpoint);

#endif
