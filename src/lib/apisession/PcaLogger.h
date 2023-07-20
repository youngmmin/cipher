/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcaLogger
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 12. 5
 *   Description        :       petra cipher logger
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCA_LOGGER_H
#define PCA_LOGGER_H

#include "DgcObject.h"
#ifdef WIN32
#include "DgcExcept.h"
#endif

class PcaLogger : public DgcObject {
   private:
    static dgt_schar LogFilePath[256];       // log file path
    static dgt_sint32 LastErrCode;           // last error code
    static dgt_time LastLogTime;             // last logging time
    static dgt_uint32 SameErrNoLogInterval;  // same error no logging interval
   protected:
   public:
    static const dgt_schar* logFilePath() { return LogFilePath; }

    static inline dgt_void logging(const char* fmt, va_list ap) {
        if (fmt == NULL) return;
        FILE* fp = (FILE*)fopen(LogFilePath, "a");
        if (fp == NULL) return;
        time_t current;
        time(&current);
        struct tm* cl = localtime(&current);
#ifdef WIN32
        fprintf(fp, "\n[%d.%02d.%02d.%02d:%02d:%02d]:", cl->tm_year + 1900,
                cl->tm_mon + 1, cl->tm_mday, cl->tm_hour, cl->tm_min,
                cl->tm_sec);
#else
        dg_fprint(fp, "\n[%d.%02d.%02d.%02d:%02d:%02d]:", cl->tm_year + 1900,
                  cl->tm_mon + 1, cl->tm_mday, cl->tm_hour, cl->tm_min,
                  cl->tm_sec);
#endif
#ifdef WIN32
        vfprintf(fp, fmt, ap);
#else
        dg_vfprintf(fp, fmt, ap);
#endif
        fflush(fp);
        fclose(fp);
    };

#ifdef WIN32
    static inline dgt_void tprintf(dgt_uint8 log_level, const char* fmt, ...) {
        va_list ap;
        va_start(ap, fmt);
        if (fmt == NULL) return;
        FILE* fp = (FILE*)fopen(LogFilePath, "a");
        if (fp == NULL) return;
        time_t current;
        time(&current);
        struct tm* cl = localtime(&current);
#ifdef WIN32
        fprintf(fp, "\n[%d.%02d.%02d.%02d:%02d:%02d]:", cl->tm_year + 1900,
                cl->tm_mon + 1, cl->tm_mday, cl->tm_hour, cl->tm_min,
                cl->tm_sec);
#else
        dg_fprint(fp, "\n[%d.%02d.%02d.%02d:%02d:%02d]:", cl->tm_year + 1900,
                  cl->tm_mon + 1, cl->tm_mday, cl->tm_hour, cl->tm_min,
                  cl->tm_sec);
#endif
#ifdef WIN32
        vfprintf(fp, fmt, ap);
#else
        dg_vfprintf(fp, fmt, ap);
#endif
        fflush(fp);
        fclose(fp);
    };

    static inline dgt_void tprintf(dgt_uint8 log_level, DgcExcept& except,
                                   const dgt_schar* fmt, ...) {
        va_list ap;
        va_start(ap, fmt);
        if (fmt == NULL) return;
        FILE* fp = (FILE*)fopen(LogFilePath, "a");
        if (fp == NULL) return;
        time_t current;
        time(&current);
        struct tm* cl = localtime(&current);

        dgt_schar ErrMsg[2048];
        memset(ErrMsg, 0, 2048);
        DgcError* err = 0;
        if ((err = except.getErr())) {
            strcat(ErrMsg, err->message());
        }

#ifdef WIN32
        fprintf(fp, "\n[%d.%02d.%02d.%02d:%02d:%02d]:", cl->tm_year + 1900,
                cl->tm_mon + 1, cl->tm_mday, cl->tm_hour, cl->tm_min,
                cl->tm_sec);
#else
        dg_fprint(fp, "\n[%d.%02d.%02d.%02d:%02d:%02d]:", cl->tm_year + 1900,
                  cl->tm_mon + 1, cl->tm_mday, cl->tm_hour, cl->tm_min,
                  cl->tm_sec);
#endif
#ifdef WIN32
        vfprintf(fp, fmt, ap);
        fprintf(fp, "[%s]\n", ErrMsg);
#else
        dg_vfprintf(fp, fmt, ap);
        dg_vfprintf(fp, ErrMsg);
#endif
        fflush(fp);
        fclose(fp);
    };

#endif

    static inline dgt_void logging(dgt_sint32 err_code,
                                   const dgt_schar* log_msg) {
        dgt_time ct = dgtime(&ct);
        if (err_code && err_code == LastErrCode &&
            (ct - LastLogTime) < SameErrNoLogInterval) {
            LastLogTime = ct;
            return;
        }
        LastLogTime = ct;
        LastErrCode = err_code;
        FILE* fp = (FILE*)fopen(LogFilePath, "a");
        if (fp == NULL) return;
        time_t current;
        time(&current);
        struct tm* cl = localtime(&current);
#ifdef WIN32
        fprintf(fp, "\n[%d.%02d.%02d.%02d:%02d:%02d]:[%d]:[%s]",
                cl->tm_year + 1900, cl->tm_mon + 1, cl->tm_mday, cl->tm_hour,
                cl->tm_min, cl->tm_sec, err_code, log_msg);
#else
        dg_fprint(fp, "\n[%d.%02d.%02d.%02d:%02d:%02d]:[%d]:[%s]",
                  cl->tm_year + 1900, cl->tm_mon + 1, cl->tm_mday, cl->tm_hour,
                  cl->tm_min, cl->tm_sec, err_code, log_msg);
#endif
        fflush(fp);
        fclose(fp);
    };

    static inline dgt_void initialize(const dgt_schar* log_file_path,
                                      dgt_uint32 no_log_interval) {
        if (log_file_path && *log_file_path)
            strncpy(LogFilePath, log_file_path, 255);
        if (no_log_interval > 0) SameErrNoLogInterval = no_log_interval;
    };
};

#endif
