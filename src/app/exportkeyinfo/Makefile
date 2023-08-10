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
all: build
build::
build_init:
build_objs: 
build_libs:
build_bins: build_pcb_exp_key_info_bin
install:: 
install_libs:
install_bins: 
uninstall:: 
uninstall_libs:
uninstall_bins: 
clean:: clean_pcb_exp_key_info_bin

#############################################################################
# petra cipher credentials manager
#
pcb_exp_key_info_bin = pcb_exp_key_info
pcb_exp_key_info_objs = \
	PcbExportKeyInfo.$(OBJEXT) 

build_pcb_exp_key_info_objs: $(pcb_exp_key_info_objs)

build_pcb_exp_key_info_bin: $(pcb_exp_key_info_objs)
	$(MAKE) bin="$(pcb_exp_key_info_bin)" \
	        objs="$(pcb_exp_key_info_objs)" \
		opt="-L$(abs_srcdir)/lib/apisession -lcipherapisession -L$(petraRootDir)/lib -lpetra -L${petraToolsDir}/lib -ltools" \
		build_bin

install_pcb_exp_key_info_bin: build_pcb_exp_key_info_bin
	$(MAKE) bin="$(pcb_exp_key_info_bin)" \
	        install_bin

uninstall_pcb_exp_key_info_bin:
	$(MAKE) bin="$(pcb_exp_key_info_bin)" \
	        uninstall_bin

clean_pcb_exp_key_info_bin:
	rm -f $(pcb_exp_key_info_bin)