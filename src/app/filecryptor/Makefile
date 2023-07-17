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
build_bins: build_pcb_file_cryptor_bin
install:: 
install_libs:
install_bins:
uninstall:: 
uninstall_libs:
uninstall_bins:
clean:: clean_pcb_file_cryptor_bin

#############################################################################
# petra cipher file_crypt manager
#
pcb_file_cryptor_bin = pcb_filecryptor
pcb_file_cryptor_objs = \
	PcbFileCryptorParam.$(OBJEXT) \
	PcbFileCryptor.$(OBJEXT) 

build_pcb_file_cryptor_objs: $(pcb_file_cryptor_objs)

build_pcb_file_cryptor_bin: $(pcb_file_cryptor_objs)
	$(MAKE) bin="$(pcb_file_cryptor_bin)" \
	        objs="$(pcb_file_cryptor_objs)" \
		opt="-L$(abs_srcdir)/lib/apisession -lcipherapisession -L$(petraRootDir)/lib -lpetra" \
		build_bin

clean_pcb_file_cryptor_bin:
	rm -f $(pcb_file_cryptor_bin)