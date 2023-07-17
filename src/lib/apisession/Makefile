#
# Makefile
#
# build:
#
# modified:
#   2023-06-26 dhkim
#
include ../../Makefile.inc

#############################################################################
# global definitions
#
all: build
build:: build_init build_objs build_libs build_bins
build_init:
build_objs: build_petra_cipher_api_session_objs build_sub_objs
build_libs: build_petra_cipher_api_session_stlib
build_bins:
install:: 
install_libs:
install_bins:
uninstall:: 
uninstall_libs:
uninstall_bins:
clean:: clean_sub_objs

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
petra_cipher_core_dir=..

# $(petra_cipher_core_dir)/Pci3DesCipher.$(OBJEXT) \
# 	$(petra_cipher_core_dir)/PciAesCipher.$(OBJEXT) \
# 	$(petra_cipher_core_dir)/PciAriaCipher.$(OBJEXT) \
# 	$(petra_cipher_core_dir)/PciDesCipher.$(OBJEXT) \
# 	$(petra_cipher_core_dir)/PciHightCipher.$(OBJEXT) \
# 	$(petra_cipher_core_dir)/PciHmac.$(OBJEXT) \
# 	$(petra_cipher_core_dir)/PciHmacCipher.$(OBJEXT) \
# 	$(petra_cipher_core_dir)/PciLeaCipher.$(OBJEXT) \
# 	$(petra_cipher_core_dir)/PciSeed256Cipher.$(OBJEXT) \
# 	$(petra_cipher_core_dir)/PciSeedCipher.$(OBJEXT) \
# 	$(petra_cipher_core_dir)/PciSha2.$(OBJEXT) \
# 	$(petra_cipher_core_dir)/PciShaCipher.$(OBJEXT) \
# 	$(petra_cipher_core_dir)/PciCryptoIf.$(OBJEXT) \
# 	$(petra_cipher_core_dir)/PciKeyMgrIf.$(OBJEXT) \

petra_cipher_api_session_objs = \
	PcaKeySvrSessionPool.$(OBJEXT) \
	PcaKeySvrSessionSoha.$(OBJEXT) \
	PccLocalConnection.$(OBJEXT) \
	PcaCredentials.$(OBJEXT) \
	PcaCryptParamPool.$(OBJEXT) \
	PcaEncZonePool.$(OBJEXT) \
	PcaKcmvpModule.$(OBJEXT) \
	PcaKeySvrSession.$(OBJEXT) \
	PcaLogger.$(OBJEXT) \
	PcaNameValuePair.$(OBJEXT) \
	PcaRegEnginePool.$(OBJEXT) \
	PcaRsaKeyPool.$(OBJEXT) \
	PcaSession.$(OBJEXT) \
	PcaSessionPool.$(OBJEXT) \
	PccCryptBuffer.$(OBJEXT) \
	PccFileMemMap.$(OBJEXT) \
	PccHashTable.$(OBJEXT) \
	PccKeyMap.$(OBJEXT) \
	PccRegExprList.$(OBJEXT) \
	PccSearchEngineFactory.$(OBJEXT) \
	PcaApiSessionPool.$(OBJEXT)


petra_cipher_file_cipher_extention_objs = \
	$(petra_cipher_api_session_objs) \
	PccCipher.$(OBJEXT) \
	PccCryptDivision.$(OBJEXT) \
	PccCryptUnit.$(OBJEXT) \
	PccCryptorFactory.$(OBJEXT) \
	PccDetectUnit.$(OBJEXT) \
	PccDetector.$(OBJEXT) \
	PccFileMerger.$(OBJEXT) \
	PccFileSpliter.$(OBJEXT) \
	PccFreeCryptBufList.$(OBJEXT) \
	PccHeaderManager.$(OBJEXT) \
	PccReader.$(OBJEXT) \
	PccRunStream.$(OBJEXT) \
	PccWriter.$(OBJEXT) \
	PccFileCryptor.$(OBJEXT)

build_petra_cipher_api_session_objs : $(petra_cipher_file_cipher_extention_objs)

petra_cipher_api_session_stlib = libcipherapisession.$(AREXT)
build_petra_cipher_api_session_stlib: build_petra_cipher_api_session_objs
	$(MAKE) stlib="$(petra_cipher_api_session_stlib)" \
	        objs="$(petra_cipher_file_cipher_extention_objs) ../*.$(OBJEXT)" \
			opt="" \
			build_stlib


sub_dir = cplusplus java oracle tibero altibase mysql

build_sub_objs:
	$(MAKE) subdirs="$(sub_dir)" tag="build" visit_subdirs

clean_sub_objs:
	$(MAKE) subdirs="$(sub_dir)" tag="clean" visit_subdirs
