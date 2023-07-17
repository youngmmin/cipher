#
# Makefile
#
# build:
#
# modified:
#   2023-06-27 dhkim
#
include ../../../Makefile.inc

CXXFLAGS:=-I.. ${CXXFLAGS}

#############################################################################
# global definitions
#
all: build
build::
build_init:
build_objs: 
build_libs:
build_bins: build_pcp_crypt_manager_bin
install:: 
install_libs:
install_bins:
uninstall:: 
uninstall_libs:
uninstall_bins:
clean:: clean_pcp_crypt_manager_bin


#############################################################################
# petra cipher agent program
#
pcp_crypt_manager_bin = pcp_crypt_manager
pcp_crypt_manager_objs = \
	PccCipherAgentManager.$(OBJEXT)

build_pcp_crypt_manager_objs: $(pcp_crypt_manager_objs)

build_pcp_crypt_manager_bin: build_pcp_crypt_manager_objs
	$(MAKE) bin="$(pcp_crypt_manager_bin)" \
	        objs="$(pcp_crypt_manager_objs)" \
		opt="-L$(petraRootDir)/lib -lpetrast -L${petraToolsDir}/lib -ltoolsst" \
		build_bin

clean_pcp_crypt_manager_bin:
	rm -f $(pcp_crypt_manager_bin)
