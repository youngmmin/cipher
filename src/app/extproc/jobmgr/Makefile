#
# Makefile
#
# build:
#
# modified:
#   2023-06-27 dhkim
#
include ../../../Makefile.inc

INCLUDE_PATHS := ../ ../../

CXXFLAGS := $(CXXFLAGS) $(foreach dir, $(INCLUDE_PATHS), -I$(dir))

#############################################################################
# global definitions
#
all: build
build::
build_init:
build_objs: 
build_libs:
build_bins: build_pcp_job_mgr_bin
install:: 
install_libs:
install_bins: 
uninstall:: 
uninstall_libs:
uninstall_bins:
clean:: clean_pcp_job_mgr_bin

#############################################################################
# petra cipher kred server, pcp_kredsvr
#
pcp_job_mgr_bin = pcp_jobmgr
pcp_job_mgr_objs = \
	../ext_main.$(OBJEXT) \
	PcbJobRunner.$(OBJEXT) \
	PccDecrypt.$(OBJEXT) \
	PccEncrypt.$(OBJEXT) \
	PccJobProgress.$(OBJEXT) \
	PccRunJob.$(OBJEXT) \
	PccRunMigJob.$(OBJEXT) \
	PccRunMigSchedule.$(OBJEXT) \
	PccRunMigVerify.$(OBJEXT) \
	PccRunMigVerifySchedule.$(OBJEXT) \
	PccRunSchedule.$(OBJEXT) \
	PccRunVerify.$(OBJEXT) \
	PccRunVerifySchedule.$(OBJEXT) \
	PccStopJob.$(OBJEXT) \
	PetraCipherMigVerifySchedule.$(OBJEXT) \
	PetraCipherSchedule.$(OBJEXT) \
	PetraCipherScheduler.$(OBJEXT) \
	PccJobMgrServer.$(OBJEXT)

build_pcp_job_mgr_objs: $(pcp_job_mgr_objs)

build_pcp_job_mgr_bin: build_pcp_job_mgr_objs
	$(MAKE) bin="$(pcp_job_mgr_bin)" \
	        objs="$(pcp_job_mgr_objs)" \
		opt="-I$(abs_srcdir)/lib/cipher -L$(petraRootDir)/lib -lpetra -lextproc -L${petraToolsDir}/lib -ltools" \
		build_bin

clean_pcp_job_mgr_bin:
	rm -f $(pcp_job_mgr_bin)
