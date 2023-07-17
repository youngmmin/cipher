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


#############################################################################
# global definitions
#
all:
build::
build_init:
build_objs: 
build_libs:
build_bins: build_pcp_key_ctrl_bin
install:: 
install_libs:
install_bins:
uninstall:: 
uninstall_libs:
uninstall_bins:
clean:: clean_pcp_key_ctrl_bin

#############################################################################
# petra cipher key ctrl
#
pcp_key_ctrl_bin = pcp_key_ctrl
pcp_key_ctrl_objs = \
	PccKeyControl.$(OBJEXT) 

build_pcp_key_ctrl_objs: $(pcp_key_ctrl_objs)

build_pcp_key_ctrl_bin: build_pcp_key_ctrl_objs
	$(MAKE) bin="$(pcp_key_ctrl_bin)" \
	        objs="$(pcp_key_ctrl_objs)" \
		opt="-L$(petraRootDir)/lib -lpetra" \
		build_bin

clean_pcp_key_ctrl_bin:
	rm -f $(pcp_key_ctrl_bin)