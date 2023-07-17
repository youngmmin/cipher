/*******************************************************************
 *   File Type          :       PcaKcmvpModule
 *   Classes            :       
 *   Implementor        :       mwpark
 *   Create Date        :       2019. 03. 31
 *   Description        :       
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCA_KCMVP_MODULE_H
#define PCA_KCMVP_MODULE_H

#ifndef WIN32

#include <dlfcn.h>
#ifndef RTLD_LAZY
# define RTLD_LAZY      1
#endif  /* RTLD_LAZY */
#ifndef RTLD_NOW
# define RTLD_NOW       0
#endif  /* RTLD_NOW */
/* some systems (OSF1 V5.0) have broken RTLD_GLOBAL linkage */
#ifdef G_MODULE_BROKEN_RTLD_GLOBAL
# undef RTLD_GLOBAL
#endif /* G_MODULE_BROKEN_RTLD_GLOBAL */
#ifndef RTLD_GLOBAL
# define RTLD_GLOBAL    0
#endif  /* RTLD_GLOBAL */
#ifndef RTLD_LOCAL
# define RTLD_LOCAL     0
#endif  /* RTLD_LOCAL */

#endif

#include "DgcObject.h"

static const dgt_schar*      KCMVP_LOGGER_FILE_PATH = "/tmp/petra_cipher_api.log";
static const dgt_schar*      KCMVP_LIB_PATH1 = "/usr/lib/libklib.so";
static const dgt_schar*      KCMVP_LIB_PATH2 = "/shcsw/klib/usr/lib/libklib.so";

class PcaKcmvpModule {
  private:
	static const dgt_sint32        KCMVP_ERR_LOAD_FAILED = -30511;
	static const dgt_sint32        KCMVP_ERR_FIND_FAILED = -30512;
	static const dgt_sint32        KCMVP_ERR_NOT_LOADED  = -30513;
	void*            KCMVP_LIB_PC_API;
  protected:
  public:
	PcaKcmvpModule();
	~PcaKcmvpModule();
	dgt_sint32 initializeModule();
	dgt_uint32 kcmvp_K_CurrState();
	void	   kcmvp_logger(const char *fmt, ...);

};

#endif /* PCA_KCMVP_MODULE_H */
