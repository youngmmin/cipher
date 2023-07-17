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
build_bins: build_pcp_meta_mgr_bin build_sub_objs
install:: 
install_libs:
install_bins: 
uninstall:: 
uninstall_libs:
uninstall_bins:
clean:: clean_pcp_meta_mgr_bin clean_sub_objs

#############################################################################
# petra cipher kred server, pcp_kredsvr
#
pcp_meta_mgr_bin = pcp_metamgr
pcp_meta_mgr_objs = \
	../ext_main.$(OBJEXT) \
	PccAgentTableTest.$(OBJEXT) \
	PccAgentTest.$(OBJEXT) \
	PccChangeScript.$(OBJEXT) \
	PccDropAgent.$(OBJEXT) \
	PccGenScript.$(OBJEXT) \
	PccGenScript2.$(OBJEXT) \
	PccGenScriptAddCol.$(OBJEXT) \
	PccGenScriptColAdmin.$(OBJEXT) \
	PccGenScriptMig.$(OBJEXT) \
	PccGetScript.$(OBJEXT) \
	PccGetTablespace.$(OBJEXT) \
	PccInstAgentPkg.$(OBJEXT) \
	PccInstAgentUser.$(OBJEXT) \
	PccMetaProcedure.$(OBJEXT) \
	PccMigValidTest.$(OBJEXT) \
	PccMyScriptBuilder.$(OBJEXT) \
	PccOraScriptBuilder.$(OBJEXT) \
	PccPostgresScriptBuilder.$(OBJEXT) \
	PccProcSessSqlText.$(OBJEXT) \
	PccProcSessionMonitor.$(OBJEXT) \
	PccRunScript.$(OBJEXT) \
	PccScriptBuilder.$(OBJEXT) \
	PccScriptBuilderFactory.$(OBJEXT) \
	PccTds2000ScriptBuilder.$(OBJEXT) \
	PccTdsScriptBuilder.$(OBJEXT) \
	PccTiberoScriptBuilder.$(OBJEXT) \
	PccTryDbConn.$(OBJEXT) \
	PccMetaMgrServer.$(OBJEXT)

build_pcp_meta_mgr_objs: $(pcp_meta_mgr_objs)

build_pcp_meta_mgr_bin: build_pcp_meta_mgr_objs
	$(MAKE) bin="$(pcp_meta_mgr_bin)" \
	        objs="$(pcp_meta_mgr_objs)" \
		opt="-L$(abs_srcdir)/lib/apisession -lcipherapisession -L$(petraRootDir)/lib -lextproc -L${petraToolsDir}/lib -ltools" \
		build_bin

clean_pcp_meta_mgr_bin:
	rm -f $(pcp_meta_mgr_bin)

sub_dir = job migverify

build_sub_objs:
	$(MAKE) subdirs="$(sub_dir)" tag="build" visit_subdirs

clean_sub_objs:
	$(MAKE) subdirs="$(sub_dir)" tag="clean" visit_subdirs