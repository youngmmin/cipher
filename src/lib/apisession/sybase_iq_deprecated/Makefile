#
# Makefile
#
# build:
#
# modified:
#   2023-06-26 dhkim
#
include ../../../Makefile.inc

#############################################################################
# global definitions
#
all:
build::
build_init:
build_objs: build_petra_cipher_sybase_iq_objs 
build_libs: build_petra_cipher_sybase_iq_shlib
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

petra_cipher_sybase_iq_objs = \
	PcaSybaseIq.$(OBJEXT)

build_petra_cipher_sybase_iq_objs : $(petra_cipher_sybase_iq_objs)

petra_cipher_sybase_iq_shlib = libPcaSybaseIq.$(SOEXT)
build_petra_cipher_sybase_iq_shlib: build_petra_cipher_sybase_iq_objs
	$(MAKE) shlib="$(petra_cipher_sybase_iq_shlib)" \
	        objs="../../*.$(OBJEXT) ../*.$(OBJEXT) $(petra_cipher_sybase_iq_objs)" \
					opt="-L$(petraRootDir)/lib -lpetrast -L$(petraToolsDir)/lib -ltoolsst -lstdc++" \
					build_shlib

