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
build_bins: build_pcb_trace_changer_bin
install:: 
install_libs:
install_bins:
uninstall:: 
uninstall_libs:
uninstall_bins:
clean:: clean_pcb_trace_changer_bin

#############################################################################
# petra cipher file_crypt manager
#
pcb_trace_changer_bin = pcb_trace_changer
pcb_trace_changer_objs = \
	../../lib/apisession/PccFileMemMap.$(OBJEXT) \
	PccTraceChanger.$(OBJEXT) 

build_pcb_trace_changer_objs: $(pcb_trace_changer_objs)

build_pcb_trace_changer_bin: $(pcb_trace_changer_objs)
	$(MAKE) bin="$(pcb_trace_changer_bin)" \
	        objs="$(pcb_trace_changer_objs)" \
		opt="-L$(petraRootDir)/lib -lpetra -L${petraToolsDir}/lib -ltools" \
		build_bin

clean_pcb_trace_changer_bin:
	rm -f $(pcb_trace_changer_bin)