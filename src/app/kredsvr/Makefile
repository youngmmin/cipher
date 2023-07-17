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
build_bins: build_pcp_kred_svr_bin
install:: 
install_libs:
install_bins: 
uninstall:: 
uninstall_libs:
uninstall_bins:
clean:: clean_pcp_key_ctrl_bin

#############################################################################
# petra cipher kred server, pcp_kredsvr
#
pcp_kred_svr_bin = pcp_kredsvr
pcp_kred_svr_objs = \
	PccKredService.$(OBJEXT) \
	PccKredSessionPool.$(OBJEXT) \
	PccKredStmt.$(OBJEXT) \
	PccKredStmtAlert.$(OBJEXT) \
	PccKredStmtApprove.$(OBJEXT) \
	PccKredStmtCrypt.$(OBJEXT) \
	PccKredStmtDetectFileGetRequest.$(OBJEXT) \
	PccKredStmtDetectFileLogData.$(OBJEXT) \
	PccKredStmtDetectFileLogRequest.$(OBJEXT) \
	PccKredStmtEncCount.$(OBJEXT) \
	PccKredStmtFileLogRequest.$(OBJEXT) \
	PccKredStmtGetCryptParam.$(OBJEXT) \
	PccKredStmtGetEci.$(OBJEXT) \
	PccKredStmtGetIV.$(OBJEXT) \
	PccKredStmtGetKey.$(OBJEXT) \
	PccKredStmtGetKeySet.$(OBJEXT) \
	PccKredStmtGetPriv.$(OBJEXT) \
	PccKredStmtGetRegEngine.$(OBJEXT) \
	PccKredStmtGetRegEngineId.$(OBJEXT) \
	PccKredStmtGetRsaKey.$(OBJEXT) \
	PccKredStmtGetTrailer.$(OBJEXT) \
	PccKredStmtGetVKeyDbPriv.$(OBJEXT) \
	PccKredStmtGetVKeyFilePriv.$(OBJEXT) \
	PccKredStmtGetVKeyPriv.$(OBJEXT) \
	PccKredStmtGetZoneId.$(OBJEXT) \
	PccKredStmtGetZoneParam.$(OBJEXT) \
	PccKredStmtLogRequest.$(OBJEXT) \
	PccKredStmtOpenSess.$(OBJEXT) \
	PccKredStmtPost.$(OBJEXT) \
	PccKredStmtPutExtKey.$(OBJEXT) \
	PccKredStmtUserFileLogRequest.$(OBJEXT) \
	PccKredServer.$(OBJEXT)

build_pcp_kred_svr_objs: $(pcp_kred_svr_objs)

build_pcp_kred_svr_bin: build_pcp_kred_svr_objs
	$(MAKE) bin="$(pcp_kred_svr_bin)" \
	        objs="$(pcp_kred_svr_objs)" \
		opt="-L$(abs_srcdir)/lib/apisession -lcipherapisession -L$(petraRootDir)/lib -lpetrast -L${petraToolsDir}/lib -ltoolsst" \
		build_bin

clean_pcp_kred_svr_bin:
	rm -f $(pcp_kred_svr_bin)
