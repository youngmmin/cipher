#
# Makefile
#
# build:
#
# modified:
#   2023-06-26 dhkim
#
include ../../Makefile.inc

#############################################################################
# global definitions
#
all:
build:: 
build_init:
build_objs: build_ext_main_objs build_sub_objs
build_libs: 
build_bins:
install:: 
install_libs:
install_bins:
uninstall::
uninstall_libs:
uninstall_bins:
clean:: clean_sub_objs

ext_main_objs: \
	ext_main.$(OBJEXT)

build_ext_main_objs: $(main_objs)

sub_dir = keymgr metamgr jobmgr filecipher

build_sub_objs:
	$(MAKE) subdirs="$(sub_dir)" tag="build" visit_subdirs

clean_sub_objs:
	$(MAKE) subdirs="$(sub_dir)" tag="clean" visit_subdirs