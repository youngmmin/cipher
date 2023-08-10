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
build_bins: build_pcp_mig_verify_bin
install:: 
install_libs:
install_bins: 
uninstall:: 
uninstall_libs:
uninstall_bins:
clean:: clean_pcp_mig_verify_bin

#############################################################################
# petra cipher kred server, pcp_kredsvr
#
pcp_mig_verify_bin = mig_verify
pcp_mig_verify_objs = \
	../PccMyScriptBuilder.$(OBJEXT) \
	../PccOraScriptBuilder.$(OBJEXT) \
	../PccPostgresScriptBuilder.$(OBJEXT) \
	../PccScriptBuilder.$(OBJEXT) \
	../PccScriptBuilderFactory.$(OBJEXT) \
	../PccTds2000ScriptBuilder.$(OBJEXT) \
	../PccTdsScriptBuilder.$(OBJEXT) \
	../PccTiberoScriptBuilder.$(OBJEXT) \
	PetraCipherMigVerifyJob.$(OBJEXT)

build_pcp_mig_verify_objs: $(pcp_mig_verify_objs)

build_pcp_mig_verify_bin: build_pcp_mig_verify_objs
	$(MAKE) bin="$(pcp_mig_verify_bin)" \
	        objs="$(pcp_mig_verify_objs)" \
		opt="-L$(abs_srcdir)/lib/apisession -lcipherapisession -L$(petraRootDir)/lib -lpetra -lextproc -L${petraToolsDir}/lib -ltools" \
		build_bin

clean_pcp_mig_verify_bin:
	rm -f $(pcp_mig_verify_bin)
