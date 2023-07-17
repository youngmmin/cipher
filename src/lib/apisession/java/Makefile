#
# Makefile
#
# build:
#
# modified:
#   2023-06-26 dhkim
#
include ../../../Makefile.inc

# REVISION := $(shell svn info | grep "Revision:" | awk '{print $$2}')
REVISION := 1004
CXXFLAGS := -DLIBRARY_VERSION=$(REVISION) ${CXXFLAGS}

#############################################################################
# global definitions
#
all:
build::
build_init:
build_objs: build_petra_cipher_java_objs 
build_libs: build_petra_cipher_java_shlib
build_bins:
install:: 
install_libs:
install_bins:
uninstall:: 
uninstall_libs:
uninstall_bins:
clean::

ifeq ($(ENABLE_B64),0)
  objmode = 32
  else
  objmode = 64
endif

syslibs =
ifeq ($(target_platform),aix4)
  syslibs = -lc -ldl -lld -lperfstat
endif
ifeq ($(target_platform),aix5)
 f-stub.oo syslibs = -lc -ldl -lld -lperfstat
endif
ifeq ($(target_platform),aix6)
  syslibs = -lc -ldl -lld -lperfstat
endif
ifeq ($(target_platform),hpux11)
  syslibs =  -lstd_v2 -lCsup_v2 -lstdc++ -lgcc
  ifeq ($(objmode),64)
  shlibs = cxaf-stub.oo jvrc-stub.oo
  endif
endif
dg_stlibs = -lstdc++ $(syslibs)

##############################################################################
# build cipher object
#

petra_cipher_java_objs = \
	sinsiway_PcaSession.$(OBJEXT)

build_petra_cipher_java_objs : $(petra_cipher_java_objs)

petra_cipher_java_shlib = libpcjapi.$(SOEXT)
build_petra_cipher_java_shlib: build_petra_cipher_java_objs
	$(MAKE) shlib="$(petra_cipher_java_shlib)" \
	        objs="../../*.$(OBJEXT) ../*.$(OBJEXT) $(petra_cipher_java_objs)" \
					opt="-L$(petraRootDir)/lib -lpetrast -L$(petraToolsDir)/lib -ltoolsst -lstdc++" \
					build_shlib

