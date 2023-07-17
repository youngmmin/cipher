#
# Makefile
#
# build:
#
# modified:
#   2023-06-27 dhkim
#
include ../../../../Makefile.inc

INCLUDE_PATHS := ../ ../../ ../../../

CXXFLAGS := $(CXXFLAGS) $(foreach dir, $(INCLUDE_PATHS), -I$(dir))

#############################################################################
# global definitions
#
all: build
build::
build_init:
build_objs: 
build_libs:
build_bins: build_pcp_job_bin
install:: 
install_libs:
install_bins: 
uninstall:: 
uninstall_libs:
uninstall_bins:
clean:: clean_pcp_job_bin

#############################################################################
# petra cipher kred server, pcp_kredsvr
#
pcp_job_bin = pcb_job
pcp_job_objs = \
	PcbCipherColumn.$(OBJEXT) \
	PcbCipherTable.$(OBJEXT) \
	PcbCollector.$(OBJEXT) \
	PcbDataChunk.$(OBJEXT) \
	PcbDataChunkPool.$(OBJEXT) \
	PcbOracleSelectStmt.$(OBJEXT) \
	PcbOracleUpdateStmt.$(OBJEXT) \
	PcbSelectStmt.$(OBJEXT) \
	PcbStmtFactory.$(OBJEXT) \
	PcbUpdateStmt.$(OBJEXT) \
	PcbUpdater.$(OBJEXT) \
	PcbVerifOraUpdateStmt.$(OBJEXT) \
	PcbWorker.$(OBJEXT) \
	../PccMyScriptBuilder.$(OBJEXT) \
	../PccOraScriptBuilder.$(OBJEXT) \
	../PccPostgresScriptBuilder.$(OBJEXT) \
	../PccScriptBuilder.$(OBJEXT) \
	../PccScriptBuilderFactory.$(OBJEXT) \
	../PccTds2000ScriptBuilder.$(OBJEXT) \
	../PccTdsScriptBuilder.$(OBJEXT) \
	../PccTiberoScriptBuilder.$(OBJEXT) \
	PetraCipherJob.$(OBJEXT)

build_pcp_job_objs: $(pcp_job_objs)

build_pcp_job_bin: build_pcp_job_objs
	$(MAKE) bin="$(pcp_job_bin)" \
	        objs="$(pcp_job_objs)" \
		opt="-L$(abs_srcdir)/lib/apisession -lcipherapisession -L$(petraRootDir)/lib -lextproc -L${petraToolsDir}/lib -ltools" \
		build_bin

clean_pcp_job_bin:
	rm -f $(pcp_job_bin)
