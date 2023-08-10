#
# Makefile
#
# build:
#
# modified:
#   2023-06-27 dhkim
#
include ../../../Makefile.inc

INCLUDE_PATHS := ../ ../../ $(abs_srcdir)/app/schedule $(abs_srcdir)/app/schedule/agent

CXXFLAGS := $(CXXFLAGS) $(foreach dir, $(INCLUDE_PATHS), -I$(dir))

#############################################################################
# global definitions
#
all: build
build::
build_init:
build_objs: 
build_libs:
build_bins: build_pcp_file_cipher_bin
install:: 
install_libs:
install_bins: 
uninstall:: 
uninstall_libs:
uninstall_bins:
clean:: clean_pcp_file_cipher_bin

#############################################################################
# petra cipher kred server, pcp_kredsvr
#
pcp_file_cipher_bin = ext_filecipher
pcp_file_cipher_objs = \
	../ext_main.$(OBJEXT) \
	PfccAgentParamBuilder.$(OBJEXT) \
	PfccAgentProcSvr.$(OBJEXT) \
	PfccAgentProcedure.$(OBJEXT) \
	PfccAgentSessionPool.$(OBJEXT) \
	PfccAlertDeadProcess.$(OBJEXT) \
	PfccCryptFile.$(OBJEXT) \
	PfccCryptStatCollector.$(OBJEXT) \
	PfccDeleteCryptStat.$(OBJEXT) \
	PfccGetAgentStat.$(OBJEXT) \
	PfccGetDetectInfo.$(OBJEXT) \
	PfccGetDetectStat.$(OBJEXT) \
	PfccGetDirCryptStat.$(OBJEXT) \
	PfccGetFileInfo.$(OBJEXT) \
	PfccGetStreamStat.$(OBJEXT) \
	PfccGetTargetList.$(OBJEXT) \
	PfccHasAgentSession.$(OBJEXT) \
	PfccPcfsGetList.$(OBJEXT) \
	PfccPcfsGetStat.$(OBJEXT) \
	PfccPcfsMount.$(OBJEXT) \
	PfccRecollectCryptDir.$(OBJEXT) \
	PfccRemoveFile.$(OBJEXT) \
	PfccSetAgentParam.$(OBJEXT) \
	PfccSyncTable.$(OBJEXT) \
	PfccValidationFile.$(OBJEXT) \
	PfccVerifyCryptParam.$(OBJEXT) \
	PfccVerifyDetectInfo.$(OBJEXT) \
	PfccVerifyExpr.$(OBJEXT) \
	PfccFileCipherServer.$(OBJEXT)

build_pcp_file_cipher_objs: $(pcp_file_cipher_objs)

build_pcp_file_cipher_bin: build_pcp_file_cipher_objs
	$(MAKE) bin="$(pcp_file_cipher_bin)" \
	        objs="$(pcp_file_cipher_objs)" \
		opt="-L$(abs_srcdir)/lib/apisession -lcipherapisession -L$(petraRootDir)/lib -lpetra -lextproc -L${petraToolsDir}/lib -ltools" \
		build_bin

clean_pcp_file_cipher_bin:
	rm -f $(pcp_file_cipher_bin)