#!/bin/sh 
# 
# bootstrap.sh -- Create auto-magic stuff for Kannel project
#
# Alexander Malysh


#
# verbose
#
set -x

#
# set automake version that needed
#
export WANT_AUTOMAKE=1.8

#
# libtool stuff
#
libtoolize --copy --automake --force

#
# and auto-magic stuff
#
aclocal 
autoheader 
autoconf 
automake --add-missing --copy --gnu
