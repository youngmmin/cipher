#
# Makefile
#
# build:
#
# modified:
#   2023-06-27 dhkim
#
include ../../../Makefile.inc

#############################################################################
# global definitions
#
all: build
build::
build_init:
build_objs: 
build_libs:
build_bins: build_pcp_key_mgr_bin
install:: 
install_libs:
install_bins: 
uninstall:: 
uninstall_libs:
uninstall_bins:
clean:: clean_pcp_key_mgr_bin

#############################################################################
# petra cipher kred server, pcp_kredsvr
#
pcp_key_mgr_bin = pcp_keymgr
pcp_key_mgr_objs = \
	../ext_main.$(OBJEXT) \
	PccChangePw.$(OBJEXT) \
	PccCloseKey.$(OBJEXT) \
	PccCreateExtIV.$(OBJEXT) \
	PccCreateExtKey.$(OBJEXT) \
	PccCreateKey.$(OBJEXT) \
	PccCreateRsaKey.$(OBJEXT) \
	PccDropExtIV.$(OBJEXT) \
	PccDropExtKey.$(OBJEXT) \
	PccDropKey.$(OBJEXT) \
	PccExportExtIV.$(OBJEXT) \
	PccExportExtKey.$(OBJEXT) \
	PccExportKey.$(OBJEXT) \
	PccGetCredentials.$(OBJEXT) \
	PccGetKey.$(OBJEXT) \
	PccImportExtIV.$(OBJEXT) \
	PccImportExtKey.$(OBJEXT) \
	PccImportKey.$(OBJEXT) \
	PccOpenKey.$(OBJEXT) \
	PccSetKeyOpenMode.$(OBJEXT) \
	PccKeyMgrServer.$(OBJEXT)

build_pcp_key_mgr_objs: $(pcp_key_mgr_objs)

build_pcp_key_mgr_bin: build_pcp_key_mgr_objs
	$(MAKE) bin="$(pcp_key_mgr_bin)" \
	        objs="$(pcp_key_mgr_objs)" \
		opt="-L$(abs_srcdir)/lib/apisession -lcipherapisession -L$(petraRootDir)/lib -lextproc -L${petraToolsDir}/lib -ltools" \
		build_bin

clean_pcp_key_mgr_bin:
	rm -f $(pcp_key_mgr_bin)
