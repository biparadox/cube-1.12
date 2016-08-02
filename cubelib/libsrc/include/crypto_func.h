#ifndef  CRYPTO_FUNC_H
#define  CRYPTO_FUNC_H
#define DIGEST_SIZE 32

int digest_to_uuid(BYTE *digest,char *uuid);
int comp_proc_uuid(char * dev_uuid,char * proc_name,char * conn_uuid);
int calculate_by_context(char **buffer,int countline,UINT32 *SM3_hash);
int calculate_sm3(char* filename, UINT32 *SM3_hash);
int calculate_pathsm3(char* filepath, UINT32 *SM3_hash);
int calculate_context_sm3(char* context, int context_size, UINT32 *SM3_hash);
int calculate_context_sha1(char* context,int context_size,uint32_t *SM3_hash);
int calculate_sha1(char* filename,unsigned char *digest);
int extend_pcr_sm3digest(BYTE * pcr_value,BYTE * sm3digest);

int bitmap_set(char * bitmap, int site);
int bitmap_clear(char * bitmap, int site);
int bitmap_get(char * bitmap, int site);
int bitmap_is_allset(char * bitmap,int size);
#endif
