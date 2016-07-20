/*************************************************
*       project:        973 trust demo, zhongan secure os 
*                       and trust standard verify
*	name:		typefind_defno.h
*	write date:    	2011-08-04
*	auther:    	Hu jun
*       content:        this file describe the different typefind define no 
*       		in the policy lib
*       changelog:       
*************************************************/
#ifndef _OS210_TYPEFIND_DEFNO_H
#define _OS210_TYPEFIND_DEFNO_H

enum authuser_typefind_type
{
	FINDTYPE_AUTHUSER_USERNAME=1,
};
enum object_typefind_type
{
	FINDTYPE_FILENAME_UNINAME=1,
	FINDTYPE_FILENAME_MATCH,
};
#endif
