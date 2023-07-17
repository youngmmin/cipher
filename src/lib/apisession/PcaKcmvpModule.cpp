/*******************************************************************
 *   File Type          :       class
 *   Classes            :       PcaKcmvpModule
 *   Implementor        :       mwpark
 *   Create Date        :       2018. 03. 31
 *   Description        :       
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PcaKcmvpModule.h"


typedef unsigned int (*KCMVP_K_CurrState_type)();

static KCMVP_K_CurrState_type K_CurrState_fp = 0;

static char PcAPIDL_ifs[1][33]={
   "K_CurrState"
};

PcaKcmvpModule::PcaKcmvpModule()
{
	KCMVP_LIB_PC_API=0;
}

PcaKcmvpModule::~PcaKcmvpModule()
{
}

dgt_sint32 PcaKcmvpModule::initializeModule()
{
        if (KCMVP_LIB_PC_API == 0) {
                kcmvp_logger("openLibrary[%s] starts",KCMVP_LIB_PATH1);
                int     mode = RTLD_NOW | RTLD_LOCAL;
#if defined ( RTLD_MEMBER )     /* for aix */
                mode |= RTLD_MEMBER;
#endif
                if ((KCMVP_LIB_PC_API=dlopen(KCMVP_LIB_PATH1, mode)) == 0) {
                        kcmvp_logger("dlopen[%s]:%s",KCMVP_LIB_PATH1,dlerror());
                        if ((KCMVP_LIB_PC_API=dlopen(KCMVP_LIB_PATH2, mode)) == 0) {
                                kcmvp_logger("dlopen[%s]:%s",KCMVP_LIB_PATH2,dlerror());
                        	return KCMVP_ERR_LOAD_FAILED;
                        }
                }
        }
        return 0;

}

dgt_uint32 PcaKcmvpModule::kcmvp_K_CurrState()
{
#ifndef WIN32
	if (K_CurrState_fp == 0) {
                if (KCMVP_LIB_PC_API == 0 && initializeModule() < 0) return KCMVP_ERR_LOAD_FAILED;
                if ((K_CurrState_fp=(KCMVP_K_CurrState_type)dlsym(KCMVP_LIB_PC_API,"K_CurrState")) == 0) {
                        kcmvp_logger("dlsym[K_CurrState]:%s",dlerror());
                        return KCMVP_ERR_FIND_FAILED;
                }
	}
	return K_CurrState_fp();
#else
	return 0;
#endif
}

void PcaKcmvpModule::kcmvp_logger(const char *fmt, ...)
{
	FILE*       fp;
	struct tm*  cl;
	time_t      current;
	if (fmt == NULL) return;
	fp=(FILE*)fopen(KCMVP_LOGGER_FILE_PATH,"a");
	if (fp == NULL) return;
	time(&current);
	cl=localtime(&current);
	fprintf(fp,"\n[%d.%02d.%02d.%02d:%02d:%02d] : ",
                        cl->tm_year+1900,
                        cl->tm_mon+1,
                        cl->tm_mday,
                        cl->tm_hour,
                        cl->tm_min,
                        cl->tm_sec);
	va_list argptr;
	va_start(argptr, fmt);
	vfprintf(fp, fmt, argptr);
	va_end(argptr);
	fflush(fp);
	fclose(fp);
	return;
}


