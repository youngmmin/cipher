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
build_bins: build_pcb_regex_validator_bin
install:: 
install_libs:
install_bins:
uninstall:: 
uninstall_libs:
uninstall_bins:
clean:: clean_pcb_regex_validator_bin

#############################################################################
# petra cipher key ctrl
#
pcb_regex_validator_bin = pcb_regexp_validator
pcb_regex_validator_objs = \
	PcbRegexpValidator.$(OBJEXT) 

build_pcb_regex_validator_objs: $(pcb_regex_validator_objs)

build_pcb_regex_validator_bin: build_pcb_regex_validator_objs
	$(MAKE) bin="$(pcb_regex_validator_bin)" \
	        objs="$(pcb_regex_validator_objs)" \
		opt="-L$(petraRootDir)/lib -lpetrast -L${petraToolsDir}/lib -ltoolsst" \
		build_bin

clean_pcb_regex_validator_bin:
	rm -f $(pcb_regex_validator_bin)