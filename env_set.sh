#!/bin/sh
LIBPATH=../cubelib/
ln -s $LIBPATH/include .
ln -s $LIBPATH/lib .
cd manager
ln -s ../include .
ln -s ../lib .
ln -s ../cloud_config.h .
return 0

