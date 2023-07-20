#
# Makefile
#
# build:
#
# modified:
#   2023-06-27 dhkim
#
include ../../../Makefile.inc

CXXFLAGS:=-I.. -I../../../lib -I../../../apisession ${CXXFLAGS}

#############################################################################
# global definitions
#
all: build
build::
build_init:
build_objs: 
build_libs:
build_bins: build_pcp_crypt_agent_bin
install:: 
install_libs:
install_bins: 
uninstall:: 
uninstall_libs:
uninstall_bins: 
clean:: clean_pcp_crypt_agent_bin


#############################################################################
# petra cipher agent program
#
pcp_crypt_agent_bin = pcp_crypt_agent
pcp_crypt_agent_objs = \
	PccAgentCryptJob.$(OBJEXT) \
	PccAgentCryptJobPool.$(OBJEXT) \
	PccAgentCursor.$(OBJEXT) \
	PccAgentCursorTable.$(OBJEXT) \
	PccAgentRepository.$(OBJEXT) \
	PccAgentStmt.$(OBJEXT) \
	PccCipherAgentSvrSession.$(OBJEXT) \
	PccCipherAgentSvrSessionPool.$(OBJEXT) \
	PccCorePool.$(OBJEXT) \
	PccCryptDir.$(OBJEXT) \
	PccCryptDirPool.$(OBJEXT) \
	PccCryptFileStmt.$(OBJEXT) \
	PccCryptManager.$(OBJEXT) \
	PccCryptManagerPool.$(OBJEXT) \
	PccCryptMir.$(OBJEXT) \
	PccCryptSchedule.$(OBJEXT) \
	PccCryptTargetCollector.$(OBJEXT) \
	PccCryptTargetFileQueue.$(OBJEXT) \
	PccCryptZone.$(OBJEXT) \
	PccCryptZonePool.$(OBJEXT) \
	PccDropJobStmt.$(OBJEXT) \
	PccGetAgentInfoStmt.$(OBJEXT) \
	PccGetCryptStatStmt.$(OBJEXT) \
	PccGetDetectInfoStmt.$(OBJEXT) \
	PccGetDirCryptStatStmt.$(OBJEXT) \
	PccGetDirEntryStmt.$(OBJEXT) \
	PccGetStreamStatStmt.$(OBJEXT) \
	PccGetTargetListStmt.$(OBJEXT) \
	PccJobRepository.$(OBJEXT) \
	PccPcfsGetListStmt.$(OBJEXT) \
	PccPcfsGetStatStmt.$(OBJEXT) \
	PccPcfsMountStmt.$(OBJEXT) \
	PccRecollectCryptDirStmt.$(OBJEXT) \
	PccRemoveFileStmt.$(OBJEXT) \
	PccSetParamsStmt.$(OBJEXT) \
	PccStreamFile.$(OBJEXT) \
	PccStreamFileStatistic.$(OBJEXT) \
	PccValidationFileStmt.$(OBJEXT) \
	PccVerifyDetectInfoStmt.$(OBJEXT) \
	PccCipherAgentService.$(OBJEXT)

build_pcp_crypt_agent_objs: $(pcp_crypt_agent_objs)

build_pcp_crypt_agent_bin: build_pcp_crypt_agent_objs
	$(MAKE) bin="$(pcp_crypt_agent_bin)" \
	        objs="$(pcp_crypt_agent_objs)" \
		opt="-L$(abs_srcdir)/lib/apisession -lcipherapisession -L$(petraRootDir)/lib -lpetrast -L${petraToolsDir}/lib -ltoolsst" \
		build_bin

clean_pcp_crypt_agent_bin:
	rm -f $(pcp_crypt_agent_bin)
