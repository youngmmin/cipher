#
# Makefile
#
# build:
#
# modified:
#   2023-06-26 dhkim
#
include ../Makefile.inc

#############################################################################
# global definitions
#
all:
build::
build_init:
build_objs: build_petra_cipher_core_objs build_sub_objs
build_libs: build_petra_cipher_core_stlib
build_bins:
install::
install_libs:
install_bins:
uninstall::
uninstall_libs:
uninstall_bins:
clean:: clean_sub_objs

VPATH = .

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

petra_cipher_core_objs = \
	Pci3DesCipher.$(OBJEXT) \
	PciAesCipher.$(OBJEXT) \
	PciAriaCipher.$(OBJEXT) \
	PciDesCipher.$(OBJEXT) \
	PciHightCipher.$(OBJEXT) \
	PciHmac.$(OBJEXT) \
	PciHmacCipher.$(OBJEXT) \
	PciLeaCipher.$(OBJEXT) \
	PciSeed256Cipher.$(OBJEXT) \
	PciSeedCipher.$(OBJEXT) \
	PciSha2.$(OBJEXT) \
	PciShaCipher.$(OBJEXT) \
	PciCryptoIf.$(OBJEXT)

petra_cipehr_key_mgr_extention_objs = \
	$(petra_cipher_core_objs) \
	PciKeyMgrIf.$(OBJEXT)	

petra_cipehr_external_key_iv_extention_objs = \
	$(petra_cipehr_key_mgr_extention_objs) \
	PccExternalIV.$(OBJEXT)	\
	PccExternalKey.$(OBJEXT)

build_petra_cipher_core_objs : $(petra_cipehr_external_key_iv_extention_objs)

petra_cipher_core_stlib = libciphercore.$(AREXT)

build_petra_cipher_core_stlib: build_petra_cipher_core_objs
	$(MAKE) stlib="$(petra_cipher_core_stlib)" \
	        objs="$(petra_cipehr_external_key_iv_extention_objs)" \
			opt="" \
			build_stlib


sub_dir = apisession

build_sub_objs:
	$(MAKE) subdirs="$(sub_dir)" tag="build" visit_subdirs

clean_sub_objs:
	$(MAKE) subdirs="$(sub_dir)" tag="clean" visit_subdirs