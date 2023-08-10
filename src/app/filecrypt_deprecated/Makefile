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
build_bins: build_pcp_file_crypt_bin
install:: 
install_libs:
install_bins:
uninstall:: 
uninstall_libs:
uninstall_bins:
clean:: clean_pcp_file_crypt_bin

#############################################################################
# petra cipher file_crypt manager
#
pcp_file_crypt_bin = pcp_file_crypt
pcp_file_crypt_objs = \
	PccFileCrypt.$(OBJEXT) 

build_pcp_file_crypt_objs: $(pcp_file_crypt_objs)

build_pcp_file_crypt_bin: $(pcp_file_crypt_objs)
	$(MAKE) bin="$(pcp_file_crypt_bin)" \
	        objs="$(pcp_file_crypt_objs)" \
		opt="-L$(abs_srcdir)/lib/apisession -lcipherapisession -L$(petraRootDir)/lib -lpetrast -L${petraToolsDir}/lib -ltoolsst" \
		build_bin

clean_pcp_file_crypt_bin:
	rm -f $(pcp_file_crypt_bin)