/*************************************************
*       Hige security Linux Operating System Project
*
*	File description: 	Definition of data describe struct header file 
*	File name:		struct_deal.h
*	date:    	2008-05-09
*	Author:    	Hu jun
*************************************************/
#ifndef  STRUCT_ORG_H
#define  STRUCT_ORG_H
enum os210_struct_elem_type   // describe types could be used in the struct
{
	OS210_TYPE_STRING,   // an string with fixed size
	OS210_TYPE_INT,      // an 32-bit int
	OS210_TYPE_ENUM,      // an 32-bit enum
	OS210_TYPE_FLAG,      // an 32-bit flag
	OS210_TYPE_TIME,     // an struct of time_t
	OS210_TYPE_UCHAR,    // a unsigned octet
	OS210_TYPE_USHORT,   // a 16-bit unsigned word
	OS210_TYPE_LONGLONG, // a 64-bit longlong integer
	OS210_TYPE_BINDATA,  // a sequence of octets with fixed size
	OS210_TYPE_BITMAP,   // a sequence of octets with fixed size(just like BINDATA),but we use eight bin string (like 01001010) to show them	 
	OS210_TYPE_HEXDATA,   // a sequence of octets with fixed size(just like BINDATA),but we use 2 hex string (like ce) to show them	 
	OS210_TYPE_BINARRAY,   // an array of sequence of octets with fixed size, attr is the sequence's size, size is array's length	 
	OS210_TYPE_VSTRING,  // a string with its first 2 octets describe string's length(exclude the first two octets)
	OS210_TYPE_ESTRING,  // a variable length string ended with '\0'
	OS210_TYPE_JSONSTRING,  // a variable length string encluded in "{}", "[]" or "\"\"" or "\'\'", it is only special in struct_json, other times,
       			        // it is same as ESTRING	
	OS210_TYPE_NODATA,   // this element has no data
	OS210_TYPE_DEFINE,	//an octets sequence whose length defined by a forhead element (an uchar, an ushort or a int element), the attr parameter 
				//show the element's name, 
	OS210_TYPE_DEFSTR,	//a string whose length defined by a forhead element (an uchar, an ushort or a int element), the attr parameter 
				//show the element's name, 
	OS210_TYPE_DEFSTRARRAY,	//a fixed string' s array whose elem number defined by a forhead element (an uchar, an ushort,a int element or 
				//a string like "72", the attr parameter show the forhead element's name, the elem_attr->size show how
			 	// the string's fixed length.
				// NOTE: there should not be any ' ' in the string.
				//
	OS210_TYPE_ORGCHAIN,    // this element describes a new struct in this site, attr points to the description of the new struct
        OS210_TYPE_CHOICE,
	OS210_TYPE_ENDDATA,
		
	ASN_TYPE_TAG,
	ASN_TYPE_BOOL,
	ASN_TYPE_INT,
	ASN_TYPE_LONGINT,
	ASN_TYPE_NULL,
	ASN_TYPE_TIME,
	ASN_TYPE_OID,
	ASN_TYPE_BITSTRING,
	ASN_TYPE_OCTETSTRING,
	ASN_TYPE_OIDSTRING,
	ASN_TYPE_SEQUENCE,
	ASN_TYPE_SET,
	ASN_TYPE_OPTIONAL,
	ASN_TYPE_CHOICE,
	ASN_TYPE_NAME,
	ASN_TYPE_EXTID,

	TPM_TYPE_UINT64,
	TPM_TYPE_UINT32,
	TPM_TYPE_UINT16,
	
	DB_TYPE_STRING,
	DB_TYPE_INT,
};

struct struct_elem_attr 
{
	char * name;
	enum os210_struct_elem_type type;
	int size;     //长度值,对变长变量,则为最大长度值	
	void * attr;
};

typedef struct tagnameofvalue
{
	char * name;
	int value;
}NAME2VALUE;

typedef struct tagnameofpointer
{
	char * name;
	void * pointer;
}NAME2POINTER;

enum json_elem_type
{
    JSON_ELEM_INIT,
    JSON_ELEM_NUM,
    JSON_ELEM_STRING,
    JSON_ELEM_BOOL,
    JSON_ELEM_MAP,
    JSON_ELEM_ARRAY,
    JSON_ELEM_VALUE,
    JSON_ELEM_NULL
};
// pointer stack function
void * init_pointer_stack(int size);
void free_pointer_stack(void * stack);
int pointer_stack_push(void * pointer_stack,void * pointer);
void * pointer_stack_pop(void * pointer_stack);

void * init_pointer_queue(int size);
void free_pointer_queue(void * queue);
int pointer_queue_put(void * pointer_queue,void * pointer);
int pointer_queue_get(void * pointer_queue,void **pointer);

// alloc and free the struct

void * create_struct_template(struct struct_elem_attr * struct_desc);
void free_struct_template(void * struct_template);
int free_struct(void * addr,void * struct_template);
int alloc_struct(void ** addr,void * struct_template);


int struct_2_blob(void * addr, void * blob,void * struct_template);
int struct_2_part_blob(void * addr, void * blob,void * struct_template,char * name_list);
int blob_2_struct(void * blob,void * addr,void * struct_template);
int blob_2_text(void * blob, char * string,void * struct_template, int * stroffset);
int text_2_blob(char * string,void * blob, void * struct_template, int * stroffset);

int struct_comp_elem(char * name,void * src,void * dest,void * struct_template);
int struct_comp_elem_text(char * name,void * addr,char * text,void * struct_template);
int struct_read_elem(char * name,void * addr, void * elem_data,void * struct_template);
int struct_write_elem(char * name,void * addr, void * elem_data,void * struct_template);
int struct_read_elem_text(char * name,void * addr, char * text,void * struct_template);
int struct_write_elem_text(char * name,void * addr, char * string,void * struct_template);
void * get_desc_from_template(void * struct_template);

void * dup_str(char * src,int size);
void * clone_struct(void * addr, void * struct_template);
void * struct_get_elem_attr(char * name,void * struct_template);
int struct_set_elem_var(char * name,void * attr,void * struct_template);

int struct_2_json( void * addr,char * json_str,void * template,int * stroffset);
int json_2_struct(void * root,void * addr, void * struct_template);
void * find_json_elem(char * name,void * root);
void * get_first_json_child(void * father);
void * get_next_json_child(void * father);
int get_json_value_from_node(void * node,void * value,int max_len);
int get_json_name_from_node(void * node,char * name);

int json_solve_str(void ** root, char *str);
int json_get_type(void * node);
void * read_elem_addr(char * name, void * template);
void * json_get_father(void * child);
void * Memcpy(void * dest,void * src, unsigned int count);
#endif
