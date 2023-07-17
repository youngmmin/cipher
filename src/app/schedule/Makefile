#
# Makefile
#
# build:
#
# modified:
#   2023-06-27 dhkim
#
include ../../Makefile.inc

#############################################################################
# global definitions
#



all:
build::
build_init:
build_objs: 
build_libs:
build_bins: build_sub_objs
install:: 
install_libs:
install_bins:
uninstall:: 
uninstall_libs:
uninstall_bins:
clean:: clean_sub_objs

sub_dir = manager agent

build_sub_objs:
	$(MAKE) subdirs="$(sub_dir)" tag="build" visit_subdirs

clean_sub_objs:
	$(MAKE) subdirs="$(sub_dir)" tag="clean" visit_subdirs