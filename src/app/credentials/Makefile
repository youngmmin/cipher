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
build_bins: build_pcp_credentials_bin
install:: 
install_libs:
install_bins: 
uninstall:: 
uninstall_libs:
uninstall_bins: 
clean:: clean_pcp_credentials_bin

#############################################################################
# petra cipher credentials manager
#
pcp_credentials_bin = pcp_credentials
pcp_credentials_objs = \
	PccCredentials.$(OBJEXT) 

build_pcp_credentials_objs: $(pcp_credentials_objs)

build_pcp_credentials_bin: $(pcp_credentials_objs)
	$(MAKE) bin="$(pcp_credentials_bin)" \
	        objs="$(pcp_credentials_objs)" \
		opt="-L$(abs_srcdir)/lib/apisession -lcipherapisession -L$(petraRootDir)/lib -lpetra -L${petraToolsDir}/lib -ltools" \
		build_bin

install_pcp_credentials_bin: build_pcp_credentials_bin
	$(MAKE) bin="$(pcp_credentials_bin)" \
	        install_bin

uninstall_pcp_credentials_bin:
	$(MAKE) bin="$(pcp_credentials_bin)" \
	        uninstall_bin

clean_pcp_credentials_bin:
	rm -f $(pcp_credentials_bin)