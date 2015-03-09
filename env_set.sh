#!/bin/sh
export CUBELIBPATH=/root/cube-1.1/cubelib/
ln -s $CUBELIBPATH/include .
ln -s $CUBELIBPATH/lib .
cd manager
ln -s ../include .
ln -s ../lib .
ln -s ../cloud_config.h .
cd -
return 0

