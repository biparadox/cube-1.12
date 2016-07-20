
#define os210_print_buf 4096
#define OS210_MAX_BUF   4096

//#define nulstring "NULL"

UINT16 Decode_UINT16(BYTE * in);

void UINT32ToArray(UINT32 i, BYTE * out);

void UINT64ToArray(UINT64 i, BYTE *out);

void UINT16ToArray(UINT16 i, BYTE * out);

UINT64 Decode_UINT64(BYTE *y);

UINT32 Decode_UINT32(BYTE * y);

#define  MAX_ARRAY_ELEM_NUM  128

typedef struct  tag_template_elem
{
	void   * elem_struct;
	struct struct_elem_attr * elem_desc;
	void * elem_var;
}TEMPLATE_ELEM;

struct struct_template
{
	int elem_num;
	struct tag_struct_template * parent_struct;
	struct struct_elem_attr * struct_desc;
	TEMPLATE_ELEM * elem_list;
	void * var_list;
};
const char * nulstring;
