#ifndef TIME_STAMP_FUNC_H
#define TIME_STAMP_FUNC_H

struct expand_time_stamp  //time expand data struct
{
   int  data_size;   //this expand data's size
   char tag[4];      //expand data's type
   char time [DIGEST_SIZE];
} __attribute__((packed));

static struct struct_elem_attr expand_time_stamp_desc[]=
{
    {"data_size",OS210_TYPE_INT,sizeof(int),NULL},
    {"tag",OS210_TYPE_STRING,4,NULL},
    {"time",OS210_TYPE_STRING,DIGEST_SIZE,NULL},
    {NULL,OS210_TYPE_ENDDATA,0,NULL}
};
// plugin's init func and kickstart func
int time_stamp_init(void * sub_proc,void * para);
int time_stamp_start(void * sub_proc,void * para);

#endif
