/*************************************************
*       project:        973 trust demo, zhongan secure os 
*                       and trust standard verify
*	name:		extern_interface.h
*	write date:    	2011-08-04
*	auther:    	Hu jun
*       content:        this file describe the module's extern interface 
*       changelog:       
*************************************************/
#ifndef _OS210_EXTERN_INTERFACE_H
#define _OS210_EXTERN_INTERFACE_H

#include "../include/data_type.h"

// logic module's extern function
int InitBaseLib(void);

int LoadPolicyData(BYTE * Buffer);

int logic_getsublabel(void * label,char * name,int type);

int logic_getobjlabel(void * label,char * name,int type);

char * logic_getusername(int uid);

int logic_ifuservalid(char * username);

int logic_access_verify(SUB_LABEL *SubLabel, OBJ_LABEL *ObjLabel, BYTE OPType);

int logic_verify_data(OBJ_LABEL * object,BYTE * data);

 static inline void Init_SubLabel( SUB_LABEL * sublabel)  
 {
	memset(sublabel,0,sizeof(SUB_LABEL));
 }

 static inline void Init_ObjLabel( OBJ_LABEL * objlabel)  
 {
	memset(objlabel,0,sizeof(OBJ_LABEL));
 }
#endif
