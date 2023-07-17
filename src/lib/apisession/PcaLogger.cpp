/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PcaLogger
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 12. 5
 *   Description        :       petra cipher logger
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PcaLogger.h"


#ifdef WIN32
dgt_schar       PcaLogger::LogFilePath[256] = "C:\\Program Files\\SINSIWAY\\Petra\\api\\petra_cipher_api.log";
#else
dgt_schar       PcaLogger::LogFilePath[256] = "/tmp/petra_cipher_api.log";
#endif
dgt_sint32	PcaLogger::LastErrCode = 0; // last error code
dgt_time	PcaLogger::LastLogTime = 0; // last logging time
dgt_uint32	PcaLogger::SameErrNoLogInterval = 30; // same error no logging interval
