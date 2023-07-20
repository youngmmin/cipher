/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcaKeySvrSessionPool
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 4. 7
 *   Description        :       petra cipher key server session pool
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCA_KEY_SVR_SESSION_POOL_H
#define PCA_KEY_SVR_SESSION_POOL_H

#include "DgcSpinLock.h"
#include "PcaKeySvrSession.h"
#include "PcaLogger.h"
#include "PccFileMemMap.h"

class PcaKeySvrSessionPool : public DgcObject {
   private:
    static const dgt_sint32 PKSSP_ERR_LOCK_FAIL = -30310;
    static const dgt_sint32 PKSSP_ERR_NO_SESSION = -30311;
    static const dgt_sint32 PKSSP_ERR_NO_FREE_SESSION = -30312;
    static const dgt_sint32 PKSSP_ERR_NO_EMPTY_SPACE = -30313;

    static const dgt_sint32 PKSSP_MAX_SESSIONS = 2048;  // size of session table
    static const dgt_sint32 PKSSP_GET_MAX_TRY =
        1000;  // get free session max try
    static const dgt_sint32 PKSSP_DEFAULT_ELF =
        1;  // default encrypt local flag
    static const dgt_sint32 PKSSP_DEFAULT_DLF =
        1;  // default decrypt local flag
    static const dgt_sint32 PKSSP_DEFAULT_NSI =
        0;  // default new sql interval in microsecond, 0 means this function is
            // not used
    static const dgt_sint32 PKSSP_DEFAULT_NS = 1;  // default number of sessions
    static const dgt_sint32 PKSSP_DEFAULT_SERR_NO_LOG_INTERVAL =
        30;  // same error no logging interval
    static const dgt_sint32 PKSSP_MAX_STARVE_SESSIONS =
        2048;  // size of starving session table
    static const dgt_sint32 PKSSP_STARVE_THRESHOLD = 600;  // starving threshold
    static const dgt_sint32 PKSSP_MAX_PRIVATE_SESSION =
        10000;  // the maximum number of private sessions
    static const dgt_sint32 PKSSP_THRD_SESS_CHECK_INTERVAL =
        10;  // thread session check interval
    static const dgt_sint32 PKSSP_THRD_SESS_CLEAN_INTERVAL =
        180;  // thread session clean interval
    static const dgt_sint32 PKSSP_THRD_SESS_MAX_SLEEP =
        600;  // thread session max sleep

    // static dgt_sint32	TraceLevel;				// trace level
    static dgt_sint32
        ThreadSessionCheckInterval;  // thread session check interval
    static dgt_sint32
        ThreadSessionCleanInterval;           // thread session clean interval
    static dgt_sint32 ThreadSessionMaxSleep;  // thread session max sleep
    static dgt_sint32 NumSharedSession;       // the number of shared sessions
    static dgt_sint32
        MaxPrivateSession;  // the maximum number of private sessions
    static dgt_uint32 RuleEffectiveTime;  // Rule Effective Time
#if 1
    static dgt_sint64 VlColID;      // for ibk
    static dgt_sint32 VlLength;     // for ibk
    static dgt_sint32 VlEncLength;  // for ibk
#endif
    static PccFileMemMap* TraceMemMap;  // replrace TraceLevel

    dgt_slock PoolLatch;             // spin lock for concurrency control
    dgt_sint32 EncryptLocalFlag;     // flag for encrypting locally
    dgt_sint32 DecryptLocalFlag;     // flag for decrypting locally
    dgt_sint64 NewSqlInterval;       // no request interval in micro second for
                                     // defining sql boundary
    dgt_sint32 CurrNumSessions;      // the number of current sessions
    dgt_sint32 NumStarveSessions;    // the number of starving sessions
    dgt_schar SharedSessionIP[65];   // client ip for shared session
    dgt_schar SharedSessionUID[33];  // user id for shared session
    dgt_schar SharedSessionProgram[129];  // program name for shared session
    dgt_schar DefaultEncColName[129];     // default encrypt column name
    dgt_schar IpProbCmdPath[129];         // login ip prober command path
    dgt_schar IpProbCmdArgs[129];         // login ip prober command arguments
    dgt_sint32 IpProbPos;  // login ip prober ip position in output line
    dgt_schar MacProbCmdPath[129];  // mac prober command path
    dgt_schar MacProbCmdArgs[129];  // mac prober command arguments
    dgt_sint32 MacProbIpPos;        // mac prober ip position in output line
    dgt_sint32 MacProbPos;          // mac prober mac position in output line
    dgt_schar CharSet[33];          // default character set
    dgt_schar InstanceName[33];     // default instance name
    dgt_schar DbName[33];           // default database name
    dgt_uint8 DoubleEncCheck;       // double encrypt check flag
    dgt_uint8 TrailerFlag;          // trailer flag ( 1 : add, 0 : del )
    dgt_uint8 ApiMode;              // trailer flag ( 1 : api mode, 0 : plugin )
#if 1  // added by chchung 2015.9.13 for adding test mode
    dgt_uint8 OpMode;  // operation mode ( 1 ~ 6 )
#endif
#if 1  // added by chchung 2017.6.11 for adding system level stand alone mode
    dgt_schar KeyInfoFilePath[516];  // key info file path
#endif
#if 1  // added by chchung 2017.6.20 for for allowing optional decrypting error
       // handling
    dgt_uint8 DecryptFailSrcRtnFlag;  // source return when failure of
                                      // decrypting instead of returning error
#endif
#if 1  // added by mwpark 2017.12.06 for adding system name & system ip
    dgt_schar SystemName[65];
    dgt_schar SystemIp[65];
#endif

    PcaKeySvrSession* SessionTable[PKSSP_MAX_SESSIONS];  // server session table
    struct {
        dgt_sint32 degree;
        PcaKeySvrSession* svr_session;
    } StarvingQueue[PKSSP_MAX_STARVE_SESSIONS];  // starving API session queue

    //
    // udp logging for oltp service
    //
#ifndef WIN32
    dgt_uint8 OltpLogMode;            // for udp logging mode
    dgt_schar UdpHost1[65];           // udp host
    dgt_uint16 UdpPort1;              // udp port
    DgcSockDatagram ClientDatagram1;  // OltpLogMode (for udp connection)
    dgt_sint32 UdpBindFlag;
    dgt_uint8 MarshallBuffer[256];

    dgt_schar UdpHost2[65];  // udp host
    dgt_uint16 UdpPort2;
    DgcSockDatagram ClientDatagram2;  // OltpLogMode (for udp connection)
    dgt_sint32 UdpBindFlag2;
    dgt_uint8 MarshallFileBuffer[1031];
#endif

#if 1  // added by mwpark for dynamic loading klib
    dgt_sint8 KcmvpMode;
#endif

   protected:
   public:
    static inline dgt_void logging(const char* fmt, ...) {
        va_list ap;
        va_start(ap, fmt);
        PcaLogger::logging(fmt, ap);
        va_end(ap);
    };

    static inline dgt_void logging(dgt_sint32 err_code,
                                   const dgt_schar* log_msg) {
        PcaLogger::logging(err_code, log_msg);
    };

    static inline dgt_sint32 traceLevel() {
        if (TraceMemMap && TraceMemMap->isLoaded())
            return (dgt_sint32) * ((dgt_uint8*)TraceMemMap->address());
        else
            return 0;
    };
    static inline dgt_sint32 threadSessionCheckInterval() {
        return ThreadSessionCheckInterval;
    };
    static inline dgt_sint32 threadSessionCleanInterval() {
        return ThreadSessionCleanInterval;
    };
    static inline dgt_sint32 threadSessionMaxSleep() {
        return ThreadSessionMaxSleep;
    };
    static inline dgt_sint32 numSharedSession() { return NumSharedSession; };
    static inline dgt_sint32 maxPrivateSession() { return MaxPrivateSession; };
    static inline dgt_uint32 ruleEffectiveTime() { return RuleEffectiveTime; };
    static inline dgt_sint64 vlColID() { return VlColID; };
    static inline dgt_sint32 vlLength() { return VlLength; };
    static inline dgt_sint32 vlEncLength() { return VlEncLength; };

    PcaKeySvrSessionPool();
    virtual ~PcaKeySvrSessionPool();

    inline dgt_sint32 isEncryptLocal() { return EncryptLocalFlag; };
    inline dgt_sint32 isDecryptLocal() { return DecryptLocalFlag; };
    inline dgt_sint64 newSqlInterval() { return NewSqlInterval; };
    inline dgt_void setNewSqlInterval(dgt_sint64 new_sql_interval) {
        NewSqlInterval = new_sql_interval;
    };
    inline dgt_schar* sharedSessionIP() { return SharedSessionIP; };
    inline dgt_schar* sharedSessionUID() { return SharedSessionUID; };
    inline dgt_schar* sharedSessionProgram() { return SharedSessionProgram; };
    inline dgt_schar* defaultEncColName() { return DefaultEncColName; };
    inline dgt_schar* ipProbCmdPath() { return IpProbCmdPath; };
    inline dgt_schar* ipProbCmdArgs() { return IpProbCmdArgs; };
    inline dgt_sint32 ipProbPos() { return IpProbPos; };
    inline dgt_schar* macProbCmdPath() { return MacProbCmdPath; };
    inline dgt_schar* macProbCmdArgs() { return MacProbCmdArgs; };
    inline dgt_sint32 macProbIpPos() { return MacProbIpPos; };
    inline dgt_sint32 macProbPos() { return MacProbPos; };
    inline dgt_schar* charSet() { return CharSet; };
    inline dgt_schar* instanceName() { return InstanceName; };
    inline dgt_schar* dbName() { return DbName; };
    inline dgt_uint8 doubleEncCheck() { return DoubleEncCheck; };
    inline dgt_uint8 trailerFlag() { return TrailerFlag; };
    inline dgt_uint8 apiMode() { return ApiMode; };
    inline dgt_uint8 opMode() { return OpMode; };
#ifdef WIN32
    inline dgt_uint8 oltpLogMode() { return 0; };
#else
    inline dgt_uint8 oltpLogMode() { return OltpLogMode; };
#endif

#if 1  // added by chchung 2017.6.11 for adding system level standalone mode
    inline const dgt_schar* keyInfoFilePath() { return KeyInfoFilePath; }
#endif
#if 1  // added by chchung 2017.6.20 for for allowing optional decrypting error
       // handling
    inline dgt_uint8 decryptFailSrcRtn() { return DecryptFailSrcRtnFlag; }
#endif
#if 1  // added by mwpark 2017.12.06 for for adding system name & system ip
    inline dgt_schar* systemName() { return SystemName; }
    inline dgt_schar* systemIp() { return SystemIp; }
#endif
#if 1  // added by mwpark for dynamic loading klib
    inline dgt_sint8 kcmvpMode() { return KcmvpMode; }
#endif

    inline dgt_sint32 getSession(PcaKeySvrSession** session) {
        dgt_sint32 rtn = 0;
        dgt_sint32 starving_queue_id = -1;
        *session = 0;
        for (dgt_sint32 i = 0; i < PKSSP_GET_MAX_TRY && CurrNumSessions; i++) {
            if (DgcSpinLock::lock(&PoolLatch)) {
                rtn = PKSSP_ERR_LOCK_FAIL;
                logging(rtn, "locking the server session pool failed");
                break;
            } else {
                if (CurrNumSessions == 0 && (rtn = initialize())) {
                    DgcSpinLock::unlock(&PoolLatch);
                    return rtn;
                }
                if (starving_queue_id >= 0) {
                    //
                    // waiting in the starving queue
                    //
                    if (StarvingQueue[starving_queue_id].svr_session) {
                        //
                        // assigned a server session
                        //
                        *session = StarvingQueue[starving_queue_id].svr_session;
                        StarvingQueue[starving_queue_id].svr_session = 0;
                        StarvingQueue[starving_queue_id].degree = 0;
                        NumStarveSessions--;
                    } else if (i == (PKSSP_GET_MAX_TRY - 1)) {
                        //
                        // time out
                        //
                        StarvingQueue[starving_queue_id].degree = 0;
                        NumStarveSessions--;
                    } else {
                        StarvingQueue[starving_queue_id].degree++;
                    }
                } else {
                    for (dgt_sint32 j = 0; j < CurrNumSessions; j++) {
                        if (SessionTable[j]) {
                            *session = SessionTable[j];
                            SessionTable[j] = 0;
                            break;
                        }
                    }
                    if (i == PKSSP_STARVE_THRESHOLD && *session == 0) {
                        //
                        // go to the starving queue and waiting
                        //
                        for (dgt_sint32 sq_id = 0;
                             sq_id < PKSSP_MAX_STARVE_SESSIONS; sq_id++) {
                            if (StarvingQueue[sq_id].degree == 0) {
                                //
                                // find a empty queue & registering
                                //
                                starving_queue_id = sq_id;
                                StarvingQueue[sq_id].degree++;
                                NumStarveSessions++;
                                break;
                            }
                        }
                    }
                }
                DgcSpinLock::unlock(&PoolLatch);
            }
            if (*session) break;
            napAtick();
        }
        if (*session == 0) {
            rtn = PKSSP_ERR_NO_FREE_SESSION;
            if (CurrNumSessions) logging(rtn, "no free server session");
        }
        return rtn;
    };

    inline dgt_sint32 returnSession(PcaKeySvrSession* session) {
        dgt_sint32 rtn = 0;
        if (DgcSpinLock::lock(&PoolLatch)) {
            logging(PKSSP_ERR_LOCK_FAIL,
                    "locking the server session pool failed");
            rtn = PKSSP_ERR_LOCK_FAIL;
        } else {
            if (NumStarveSessions > 0) {
                //
                // searching for a starving API session
                //
                dgt_sint32 max_degree = 0;
                dgt_sint32 max_starving_id = -1;
                for (dgt_sint32 sq_id = 0; sq_id < PKSSP_MAX_STARVE_SESSIONS;
                     sq_id++) {
                    if (StarvingQueue[sq_id].degree > 0) {
                        if (StarvingQueue[sq_id].degree > max_degree) {
                            max_degree = StarvingQueue[sq_id].degree;
                            max_starving_id = sq_id;
                        }
                    }
                }
                if (max_starving_id >= 0) {
                    //
                    // found a starving API session and give the server session
                    // to it
                    //
                    StarvingQueue[max_starving_id].svr_session = session;
                    session = 0;
                }
            } else {
                for (dgt_sint32 i = 0; i < CurrNumSessions; i++) {
                    if (!SessionTable[i] || SessionTable[i] == session) {
                        SessionTable[i] = session;
                        session = 0;
                        break;
                    }
                }
            }
            DgcSpinLock::unlock(&PoolLatch);

            if (session) {
                logging(PKSSP_ERR_NO_EMPTY_SPACE,
                        "no empty space in server session pool");
                rtn = PKSSP_ERR_NO_EMPTY_SPACE;
            }
        }
        return rtn;
    };

    dgt_sint32 initialize(dgt_schar* info_file_path = 0,
                          const dgt_schar* credentials_pw = 0,
                          dgt_sint32 stand_alone_flag = 0);

    inline dgt_sint32 oltpLogging(pc_type_log_request_in* log_request) {
#ifndef WIN32
        //
        // udp connection logging mode
        //
        if (UdpBindFlag == 0) {
            //
            // try udp bind
            //
            dgt_sint32 ntry = 0;
            if (UdpPort1) {
                if (ClientDatagram1.bindSvrAddress(UdpHost1, UdpPort1) <= 0) {
                    logging("OLTP LogMode Udp[%s-%u] bind failed.", UdpHost1,
                            UdpPort1);
                    return 0;
                }
                UdpBindFlag = 1;
            } else {
                UdpBindFlag = 2;
            }
        }
        if (UdpBindFlag == 1) {
            //
            // udp bind success
            //
            memset(MarshallBuffer, 0, 256);
            mcp8((dgt_uint8*)MarshallBuffer,
                 (dgt_uint8*)&log_request->user_sid);
            mcp8((dgt_uint8*)MarshallBuffer + 8,
                 (dgt_uint8*)&log_request->enc_col_id);
            mcp8((dgt_uint8*)MarshallBuffer + 16,
                 (dgt_uint8*)&log_request->enc_count);
            mcp8((dgt_uint8*)MarshallBuffer + 24,
                 (dgt_uint8*)&log_request->dec_count);
            mcp8((dgt_uint8*)MarshallBuffer + 32,
                 (dgt_uint8*)&log_request->lapse_time);
            mcp8((dgt_uint8*)MarshallBuffer + 40,
                 (dgt_uint8*)&log_request->stmt_id);
            mcp8((dgt_uint8*)MarshallBuffer + 48,
                 (dgt_uint8*)&log_request->sql_cpu_time);
            mcp8((dgt_uint8*)MarshallBuffer + 56,
                 (dgt_uint8*)&log_request->sql_elapsed_time);
            mcp4((dgt_uint8*)MarshallBuffer + 64,
                 (dgt_uint8*)&log_request->start_date);
            mcp4((dgt_uint8*)MarshallBuffer + 68,
                 (dgt_uint8*)&log_request->sql_type);
            *(MarshallBuffer + 72) = log_request->enc_no_priv_flag;
            *(MarshallBuffer + 73) = log_request->dec_no_priv_flag;
            memcpy(MarshallBuffer + 74, &log_request->sql_hash, 65);
            memcpy(MarshallBuffer + 139, &log_request->reserved, 33);
            if (ClientDatagram1.sendData((dgt_uint8*)MarshallBuffer, 200) < 0) {
                logging("OLTP LogMode Udp[%s-%u] send failed.", UdpHost1,
                        UdpPort1);
                return 0;
            }
        } else {
            //
            // not defined udp port
            //
            return 0;
        }
#endif
        return 0;
    };
    inline dgt_sint32 oltpFileLogging(pc_type_file_request_in* log_request) {
#ifndef WIN32
        //
        // udp connection logging mode
        //
        if (UdpBindFlag2 == 0) {
            //
            // try udp bind
            //
            dgt_sint32 ntry = 0;
            if (UdpPort2) {
                if (ClientDatagram2.bindSvrAddress(UdpHost2, UdpPort2) <= 0) {
                    logging("OLTP LogMode Udp[%s-%u] bind failed.", UdpHost1,
                            UdpPort1);
                    return 0;
                }
                UdpBindFlag2 = 1;
            } else {
                UdpBindFlag2 = 2;
            }
        }
        if (UdpBindFlag2 == 1) {
            //
            // udp bind success
            //
            memset(MarshallFileBuffer, 0, 1031);
            mcp8((dgt_uint8*)MarshallFileBuffer,
                 (dgt_uint8*)&log_request->user_sid);
            memcpy(MarshallFileBuffer + 8, log_request->system_name, 65);
            memcpy(MarshallFileBuffer + 73, log_request->system_ip, 128);
            memcpy(MarshallFileBuffer + 201, log_request->file_name, 256);
            memcpy(MarshallFileBuffer + 457, log_request->enc_type, 32);
            *(MarshallFileBuffer + 489) = log_request->mode;
            memcpy(MarshallFileBuffer + 490, log_request->key_name, 130);
            mcp8((dgt_uint8*)MarshallFileBuffer + 620,
                 (dgt_uint8*)&log_request->file_size);
            mcp8((dgt_uint8*)MarshallFileBuffer + 628,
                 (dgt_uint8*)&log_request->processed_byte);
            memcpy(MarshallFileBuffer + 636, log_request->zone_name, 130);
            mcp4((dgt_uint8*)MarshallFileBuffer + 766,
                 (dgt_uint8*)&log_request->enc_start_date);
            mcp4((dgt_uint8*)MarshallFileBuffer + 770,
                 (dgt_uint8*)&log_request->enc_end_date);
            memcpy(MarshallFileBuffer + 774, log_request->err_msg, 256);
            if (ClientDatagram2.sendData((dgt_uint8*)MarshallFileBuffer, 1030) <
                0) {
                logging("OLTP LogMode Udp[%s-%u] send failed.", UdpHost2,
                        UdpPort2);
                return 0;
            }
        } else {
            //
            // not defined udp port
            //
            return 0;
        }
#endif
        return 0;
    };
};

#endif
