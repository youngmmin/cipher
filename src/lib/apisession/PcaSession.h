/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcaSession
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 4. 1
 *   Description        :       petra cipher API session
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCA_SESSION_H
#define PCA_SESSION_H

#include "PcaCryptParamPool.h"
#include "PcaEncZonePool.h"
#include "PcaKeyPool.h"
#include "PcaNamePool.h"
#include "PcaPrivilege.h"
#include "PcaRegEnginePool.h"
#include "PcaRsaKeyPool.h"
#ifdef WIN32
#include <tchar.h>
#include <tlhelp32.h>
#include <windows.h>
#else
#include "PcLoginIpProber.h"
#include "PcaCharSetCnvt.h"
#endif

#ifdef aix6
#include <procinfo.h>
#endif

#ifdef sunos5
#include <procfs.h>
#endif

#ifndef WIN32
#include "PtCharConv.h"
#endif

class PcaSession : public PcaHashNode {
   private:
    static const dgt_sint32 PS_ERR_APPROVE_REJECTED = -30318;
    static const dgt_sint32 PS_ERR_CHARSET_CONV_FAILURE = -30388;
    static const dgt_sint32 PS_ERR_MAX_COLUMN_LENGTH_EXCEED = -30389;
    static const dgt_sint32 PS_ERR_ENC_ZONE_PARAM_NOT_FOUND = -30390;
    static const dgt_sint32 PS_ERR_REG_PARAM_NOT_FOUND = -30391;
    static const dgt_sint32 PS_ERR_CRYPT_PARAM_NOT_FOUND = -30392;
    static const dgt_sint32 PS_ERR_RSA_KEY_NOT_FOUND = -30393;

    static const dgt_uint8 PS_NO_PRIV_ENCRYPT_ALERT = 1;
    static const dgt_uint8 PS_NO_PRIV_DECRYPT_ALERT = 2;
    static const dgt_uint8 PS_TOO_MANY_DECRYPT_ALERT = 3;
    static const dgt_schar PS_DFLT_MASK_CHAR = '*';
    static const dgt_schar PS_DFLT_MASK_NUM = '0';

    static const dgt_uint32 MAX_COUPON_SRC_LEN = 128;

    dgt_sint32 SID;
    dgt_sint64 UserSID;                       // session user ID
    dgt_sint32 AuthFailCode;                  // AuthFailCode
    PcaKeySvrSessionPool* KeySvrSessionPool;  // key server session pool
    PcaNamePool* NamePool;                    // encrypt column name pool
    PcaKeyPool* KeyPool;                      // key pool
    PcaIVPool* IVPool;                        // initial vector pool
    PcaPrivilegePool PrivilegePool;           // privilege pool
    PcaEncZonePool EncZonePool;               // enc zone pool
    PcaRegEnginePool RegEnginePool;           // regular engine pool
    PcaCryptParamPool CryptParamPool;         // crypt param pool
    pc_type_log_request_in CurrRequest;       // current request
    pc_type_alert_in AlertRequest;            // alert request
    struct timeval FirstCallTime;             // first crypto function call time
    struct timeval LastCallTime;              // last crypto function call time
    dgt_sint32 NewSqlFlag;                    // new sql flag
    dgt_sint32 AlertSqlFlag;                  // Alert sql flag
    dgt_sint32 ErrCode;                       // error code
    dgt_uint32 OutBufferLength;               // ouput buffer length
    dgt_uint8* OutBuffer;                     // output buffer
    dgt_sint32 InBufferLength;                // input buffer length
    dgt_uint8* InBuffer;                      // input buffer
    dgt_sint32 ConvBufferLength;              // conversion buffer length
    dgt_uint8* ConvBuffer;                    // conversion buffer
    dgt_void* ParentLink;                     // link for PcaApiSession
    dgt_schar SessCharSet[33];                // session character set

    // for file crypt stream
    dgt_uint32 FileHeaderFlag;  // file header flag (read: skip / write: create)
    dgt_uint32 FileRealBytes;   // Real read/write Bytes
    dgt_schar FileKeyName[300];  // key name for decrypt
    dgt_schar FileName[300];     // decrypt target file name
    dgt_uint32 FileFlags;        // file flags
    dgt_uint32 FileMode;         // file modes
    dgt_sint32
        ApiSid;  // added by shson for use api session with SID of PcaSession

#ifdef WIN32

#else
    PcaCharSetCnvt* CharSetCnvt;  // character set converter

    // for udp logging
    dgt_sint32 OltpLogMode;           // for udp logging mode
    dgt_schar UdpHost1[65];           // udp host
    dgt_uint16 UdpPort1;              // udp port
    DgcSockDatagram ClientDatagram1;  // OltpLogMode (for udp connection)
    dgt_sint32 UdpBindFlag;
    dgt_uint8 MashallBuffer[256];
#endif

    //
    // added 2012.10.11 for PKSS_COLUMN_NOT_FOUND error
    // where session user is not found in the current key server.
    // this problem happens when the current key server is not the owner of
    // current UserSID. in order to solve this probem, session info must be kept
    // so as to open a new session if the current key server has no session by
    // UserSID.
    //
    pc_type_open_sess_in SessInfo;

    // added by chchung 2017.5.31 for stand alone session
    PcaPrivHolder* PrivHolder;

    PcaRsaKeyPool RsaKeyPool;

    inline dgt_void setNewSqlFlag() {
        dgt_sint64 interval = 0;
        NewSqlFlag = 0;
        if (CurrRequest.start_date == 0) {
            NewSqlFlag = 1;
        } else if (KeySvrSessionPool->newSqlInterval()) {
            //
            // caculate the time interval between the last request and the
            // current request so that the current crypt request is considered
            // to come from a new sql if the interval is greater than the
            // specified threshold time in micro-seconds.
            //
            struct timeval ct;
            gettimeofday(&ct, 0);
            if (ct.tv_sec == LastCallTime.tv_sec)
                interval = ct.tv_usec - LastCallTime.tv_usec;
            else
                interval =
                    (dgt_sint64)(ct.tv_sec - LastCallTime.tv_sec) * 1000000 +
                    ct.tv_usec - LastCallTime.tv_usec;
            if (interval >= KeySvrSessionPool->newSqlInterval()) {
                if (CurrRequest.start_date) {
#if 0
					gettimeofday(&LastCallTime,0);
#else
                    LastCallTime = ct;
#endif
                    if (KeySvrSessionPool->apiMode() == 0) logCurrRequest();
                }
                NewSqlFlag = 1;
            } else {
                LastCallTime = ct;
            }
        }
        if (NewSqlFlag && KeySvrSessionPool->apiMode() == 0) setRequest();
        // if (PcaKeySvrSessionPool::traceLevel() > 5)
        // PcaKeySvrSessionPool::logging("SID[%d]:: NewSqlFlag => [%d]
        // itvl[%lld]", SID, NewSqlFlag, interval);
    };

    inline dgt_void setRequest() {
        if (KeySvrSessionPool->apiMode() == 0) {
            CurrRequest.start_date = dgtime(
                &CurrRequest
                     .start_date);  // non zero start_date means the current
                                    // request is a logging target
        } else {
            CurrRequest.start_date = 0;
        }
        CurrRequest.user_sid = UserSID;
        if (CurrRequest.enc_col_id != -1) {
            memset(CurrRequest.sql_hash, 0, 64);
            CurrRequest.sql_type = 0;
        }
        CurrRequest.enc_col_id = 0;
        CurrRequest.lapse_time = 1;
        gettimeofday(&FirstCallTime, 0);
        LastCallTime = FirstCallTime;
    };

#ifdef WIN32
    inline void ExtractFileName(dgt_schar* pFileName) {
#ifdef KERNEL_MODE
        strcpy(pFileName, "pcp_crypt_agent");
#else
        // Our file
        std::string sFile;
        sFile = pFileName;

        // Iterate the string
        std::string::reverse_iterator aIterator;
        aIterator = sFile.rbegin();

        // Our filename
        std::string sFileName;

        // Start the build
        while (aIterator != sFile.rend() && *aIterator != '\\') {
            // Take this string
            std::string sTmp;
            sTmp = *aIterator;
            sTmp += sFileName;
            sTmp.swap(sFileName);

            // Next
            ++aIterator;
        }

        // Save the data
        strcpy(pFileName, sFileName.c_str());
#endif
    }
#endif

#ifdef WIN32

#else
    inline dgt_sint32 convCharSet(dgt_schar* src, dgt_sint32 src_len,
                                  PcaPrivilege* priv,
                                  dgt_uint8 reverse_flag = 0) {
#if 1  // added by chchung 2013.9.13 for adding test mode, where character set
       // conversion should not be done
        if (KeySvrSessionPool->opMode()) return 0;
#endif
        dgt_sint32 rtn = 0;
        if ((priv->colType() == PCI_SRC_TYPE_CHAR ||
             priv->colType() == PCI_SRC_TYPE_VARCHAR) &&
            priv->multiByteFlag() > 0 && *SessCharSet) {
            dgt_schar* col_char_set = priv->charSet(&ErrCode);
            if (col_char_set == 0) {
                PcaKeySvrSessionPool::logging(ErrCode,
                                              "getKey in charSet failed");
                return -1;
            }
            if (col_char_set && *col_char_set &&
                strncasecmp(col_char_set, SessCharSet, 32)) {
                if (CharSetCnvt) {
                    if (!CharSetCnvt->isConvertable(col_char_set, SessCharSet))
                        CharSetCnvt->setCharSet(col_char_set, SessCharSet);
                } else {
                    CharSetCnvt = new PcaCharSetCnvt(col_char_set, SessCharSet);
                }
                if (ConvBufferLength < src_len * 4) {
                    delete ConvBuffer;
                    ConvBuffer =
                        new dgt_uint8[ConvBufferLength = (src_len * 4)];
                }
                if ((rtn = CharSetCnvt->convert(
                         src, src_len, (dgt_schar*)ConvBuffer, ConvBufferLength,
                         reverse_flag)) < 0) {
                    ErrCode = PS_ERR_CHARSET_CONV_FAILURE;
                }
                if (PcaKeySvrSessionPool::traceLevel() > 0)
                    PcaKeySvrSessionPool::logging(
                        "SID[%d]:: charset convert[%s:%s:%d] => result[%d->%d]",
                        SID, col_char_set, SessCharSet, reverse_flag, src_len,
                        rtn);
            }
        }
        return rtn;
    };
#endif

#if 1  // added by chchung 2013.9.13 for adding test mode
    inline dgt_uint32 extendOutBuffer(dgt_sint32 src_len) {
        if (OutBufferLength == 0) {
            delete OutBuffer;
            OutBuffer = new dgt_uint8[OutBufferLength = 4000];
        }
        if (OutBufferLength < (dgt_uint32)src_len) {
            delete OutBuffer;
            OutBuffer = new dgt_uint8[OutBufferLength = src_len + 1];
        }
        return OutBufferLength;
    };
#endif

   protected:
   public:
    PcaSession(dgt_sint32 sid, PcaKeySvrSessionPool* key_svr_session_pool,
               PcaNamePool* name_pool, PcaKeyPool* key_pool, PcaIVPool* iv_pool,
               PcaPrivHolder* priv_holder = 0)
#ifdef WIN32
        : SID(sid),
          UserSID(0),
          KeySvrSessionPool(key_svr_session_pool),
          NamePool(name_pool),
          KeyPool(key_pool),
          ErrCode(0),
          OutBufferLength(0),
          OutBuffer(0),
          InBufferLength(0),
          InBuffer(0),
          ConvBufferLength(0),
          ConvBuffer(0),
          ParentLink(0)
#else
        : SID(sid),
          UserSID(0),
          KeySvrSessionPool(key_svr_session_pool),
          NamePool(name_pool),
          KeyPool(key_pool),
          ErrCode(0),
          OutBufferLength(0),
          OutBuffer(0),
          InBufferLength(0),
          InBuffer(0),
          ConvBufferLength(0),
          ConvBuffer(0),
          ParentLink(0),
          CharSetCnvt(0),
          OltpLogMode(0),
          UdpPort1(0),
          ClientDatagram1(DgcSockDatagram::DGC_DGRAM_CLIENT, 3, 3),
          UdpBindFlag(0)
#endif
    {
        AlertSqlFlag = 0;
        memset(&CurrRequest, 0, sizeof(CurrRequest));
        memset(&AlertRequest, 0, sizeof(AlertRequest));
        memset(&FirstCallTime, 0, sizeof(FirstCallTime));
        memset(&LastCallTime, 0, sizeof(LastCallTime));
        setCharSet();

        //
        // added 2012.10.11
        //
        memset(&SessInfo, 0, sizeof(SessInfo));
        IVPool = iv_pool;

        PrivHolder = priv_holder;
        ApiSid = 0;
    };

    virtual ~PcaSession() {
#ifdef WIN32
        delete ConvBuffer;
        delete InBuffer;
        delete OutBuffer;
        if (KeySvrSessionPool->apiMode() == 0 ||
            KeySvrSessionPool->apiMode() == 2)
            logCurrRequest();
        reset();
#else
        delete CharSetCnvt;
        delete ConvBuffer;
        delete InBuffer;
        delete OutBuffer;
        if (KeySvrSessionPool->apiMode() == 0 ||
            KeySvrSessionPool->apiMode() == 2)
            logCurrRequest();
        reset();
#endif
    };

    PcaPrivilege* getPrivilege(dgt_sint64 enc_col_id, dgt_sint32 sql_type = 0);
    PcaPrivilege* getVKeyPrivilege(dgt_sint64 virtual_key_id,
                                   dgt_uint8 crypt_type, dgt_uint8 target_type,
                                   dgt_schar* name1, dgt_schar* name2,
                                   dgt_schar* name3, dgt_schar* name4,
                                   dgt_schar* name5, dgt_schar* name6,
                                   dgt_schar* name7, dgt_schar* name8,
                                   dgt_schar* name9, dgt_schar* name10);

    inline dgt_sint32 sid() { return SID; };
    inline dgt_void setParentLink(dgt_void* link) { ParentLink = link; };
    inline dgt_void* parentLink() { return ParentLink; };
    inline dgt_uint32 lastCallTime() { return LastCallTime.tv_sec; };
    inline dgt_sint32 getApiSid() { return ApiSid; };
    inline dgt_void setApiSid(dgt_sint32 api_sid) { ApiSid = api_sid; };

    inline dgt_void setCharSet(const dgt_schar* char_set = 0) {
        if (char_set)
            strncpy(SessCharSet, char_set, 32);
        else
            strncpy(SessCharSet, KeySvrSessionPool->charSet(), 32);
    };

    inline dgt_uint8* inBuffer(dgt_sint32 len = 0) {
        if (len + 32 > InBufferLength) {
            delete InBuffer;
            InBuffer = new dgt_uint8[InBufferLength = len + 32];
            if (PcaKeySvrSessionPool::traceLevel() > 0)
                PcaKeySvrSessionPool::logging("SID[%d}:: InBuffer[%d] replaced",
                                              SID, InBufferLength);
        }
        return InBuffer;
    };

    inline dgt_void reset() {
        setRequest();  // last request logging
        UserSID = 0;
        ErrCode = 0;
        memset(&CurrRequest, 0, sizeof(CurrRequest));
        memset(&AlertRequest, 0, sizeof(AlertRequest));
        memset(&FirstCallTime, 0, sizeof(FirstCallTime));
        memset(&LastCallTime, 0, sizeof(LastCallTime));
        PrivilegePool.reset();
    };

    inline dgt_sint32 openSession(
        dgt_sint32 db_sid = 0, const dgt_schar* instance_name = 0,
        const dgt_schar* db_name = 0, const dgt_schar* ip = 0,
        const dgt_schar* db_user = 0, const dgt_schar* os_user = 0,
        const dgt_schar* program = 0, dgt_uint8 protocol = 0,
        const dgt_schar* user_id = 0, const dgt_schar* mac = 0) {
        ErrCode = 0;
        dgt_schar os_user_tmp[65];
        memset(os_user_tmp, 0, 65);
        dgt_schar cmdline[256];
        memset(cmdline, 0, 256);

#if 1  // added by chchung 2013.9.13 for adding test mode
        if (KeySvrSessionPool->opMode() >= PCI_OP_NO_PULL_NO_PUSH) return SID;
#endif

#if 1  // added by chchung 2017.5.31 for stand alone session
        if (PrivHolder) {
            dgt_uint8 multi_byte_size = 0;
            if (!strcasecmp(SessCharSet, "UTF-8"))
                multi_byte_size = 3;
            else
                multi_byte_size = 2;
            for (dgt_sint32 idx = 0; idx < PrivHolder->numPrivs(); idx++) {
                PcaPrivilege* rtn;
                PrivilegePool.putPriv(
                    new PcaPrivilege(PrivHolder->encColID(idx),
                                     PrivHolder->privInfo(idx), KeyPool, IVPool,
                                     multi_byte_size),
                    &rtn);
            }
            return SID;
        }
#endif

        PcaKeySvrSession* svr_session = 0;
        if (!(ErrCode = KeySvrSessionPool->getSession(&svr_session))) {
            if (!db_sid && (!instance_name || *instance_name == 0) &&
                (!db_name || *db_name == 0) && (!ip || *ip == 0) &&
                (!db_user || *db_user == 0) && (!os_user || *os_user == 0) &&
                (!program || *program == 0) && !protocol &&
                (!user_id || *user_id == 0) && (!mac || *mac == 0)) {
                //
                // shared session
                //
                ip = KeySvrSessionPool->sharedSessionIP();
                user_id = KeySvrSessionPool->sharedSessionUID();
#if 1  // added by mwpark 2017.06.26 for program name detect
#ifdef linux
                FILE* f;
                dgt_schar file[256] = {0};
                sprintf(file, "/proc/%d/cmdline", getpid());
                f = fopen(file, "r");
                if (f) {
                    char* p = cmdline;
                    fgets(cmdline, sizeof(cmdline) / sizeof(*cmdline), f);
                    fclose(f);
                    while (*p) {
                        p += strlen(p);
                        if (*(p + 1)) {
                            *p = ' ';
                        }
                        p++;
                    }
                    program = cmdline;
                } else {
                    program = KeySvrSessionPool->sharedSessionProgram();
                }
#elif aix6
                struct procentry64 psinfo;
                pid_t pid = getpid();
                if (getprocs64(&psinfo, sizeof(struct procentry64), NULL,
                               sizeof(struct fdsinfo64), &pid, 1) < 0) {
                    program = KeySvrSessionPool->sharedSessionProgram();
                } else {
                    memcpy(cmdline, psinfo.pi_comm, strlen(psinfo.pi_comm));
                    program = cmdline;
                }
#elif defined(sunos5) || defined(sunos5_x86)
                sprintf(cmdline, getexecname(), strlen(getexecname()));
                program = cmdline;
#elif defined(hpux11) || defined(hpux11_ia64)
                struct pst_status psinfo;
                pid_t pid = getpid();
                if (pstat_getproc(&psinfo, sizeof(struct pst_status), 0, pid) <
                    0) {
                    program = KeySvrSessionPool->sharedSessionProgram();
                } else {
                    memcpy(cmdline, psinfo.pst_ucomm, strlen(psinfo.pst_ucomm));
                    program = cmdline;
                }
#elif WIN32
                DWORD dwFileNameSize =
                    GetModuleFileName(NULL, (LPWCH)cmdline, sizeof(cmdline));
                ExtractFileName(cmdline);
                program = cmdline;
#else
                program = KeySvrSessionPool->sharedSessionProgram();
#endif

#else
                program = KeySvrSessionPool->sharedSessionProgram();
#endif
#ifndef WIN32
                if (dg_getenv("LOGNAME")) {
                    strncpy(os_user_tmp, dg_getenv("LOGNAME"), 65);
                    os_user = os_user_tmp;
                }
#else
                DWORD dwSize = 65;
                GetUserName((LPWSTR)os_user_tmp, &dwSize);
                os_user = os_user_tmp;
#endif
                if (PcaKeySvrSessionPool::traceLevel() > 0)
                    PcaKeySvrSessionPool::logging(
                        "SID[%d]:: open shared session => [%s-%s%s]", SID, ip,
                        user_id, program);
            }
            if (protocol == 0) protocol = 3;

            // added by shson 18.02.28
            // for multiple threads in atypical encrypt
            // make private session (just db_user difference at shared session)
            if (db_user && strlen(db_user) > 1 && (db_user[0] == '-')) {
#ifdef linux
                FILE* f;
                dgt_schar file[256] = {0};
                sprintf(file, "/proc/%d/cmdline", getpid());
                f = fopen(file, "r");
                if (f) {
                    char* p = cmdline;
                    fgets(cmdline, sizeof(cmdline) / sizeof(*cmdline), f);
                    fclose(f);
                    while (*p) {
                        p += strlen(p);
                        if (*(p + 1)) {
                            *p = ' ';
                        }
                        p++;
                    }
                    program = cmdline;
                } else {
                    program = KeySvrSessionPool->sharedSessionProgram();
                }
#elif aix6
                struct procentry64 psinfo;
                pid_t pid = getpid();
                if (getprocs64(&psinfo, sizeof(struct procentry64), NULL,
                               sizeof(struct fdsinfo64), &pid, 1) < 0) {
                    program = KeySvrSessionPool->sharedSessionProgram();
                } else {
                    memcpy(cmdline, psinfo.pi_comm, strlen(psinfo.pi_comm));
                    program = cmdline;
                }
#elif sunos5
                sprintf(cmdline, getexecname(), strlen(getexecname()));
                program = cmdline;

#elif WIN32
                DWORD dwFileNameSize =
                    GetModuleFileName(NULL, (LPWCH)cmdline, sizeof(cmdline));
                ExtractFileName(cmdline);
                program = cmdline;
#else
                program = KeySvrSessionPool->sharedSessionProgram();
#endif
#ifndef WIN32
                if (!os_user || *os_user == 0) {
                    if (dg_getenv("LOGNAME")) {
                        strncpy(os_user_tmp, dg_getenv("LOGNAME"), 65);
                        os_user = os_user_tmp;
                    }
                }
#else
                DWORD dwSize = 65;
                GetUserName((LPWSTR)os_user_tmp, &dwSize);
                os_user = os_user_tmp;
#endif
                if (PcaKeySvrSessionPool::traceLevel() > 0)
                    PcaKeySvrSessionPool::logging(
                        "SID[%d]:: open file agent session => [%s-%s-%s-%s]",
                        SID, ip, os_user, program, db_user);
            }

            //
            // added by mwpark
            // if client_ip is null setting shared_session_ip
            //
            if (!ip || *ip == 0) ip = KeySvrSessionPool->sharedSessionIP();
            if (!program || *program == 0)
                program = KeySvrSessionPool->sharedSessionProgram();

            //
            // added by chchung, 2012.11.01, to get session attributes from
            // credentials
            //
            const dgt_schar* val;
            if ((val = svr_session->credentials().ip()) && *val) ip = val;
            if ((val = svr_session->credentials().mac()) && *val) mac = val;
            if ((val = svr_session->credentials().instanceName()) && *val)
                instance_name = val;
            if ((val = svr_session->credentials().dbName()) && *val)
                db_name = val;
            if ((val = svr_session->credentials().dbUser()) && *val)
                db_user = val;
            if ((val = svr_session->credentials().osUser()) && *val)
                os_user = val;
            if ((val = svr_session->credentials().program()) && *val)
                program = val;
            if ((val = svr_session->credentials().orgUserID()) && *val)
                user_id = val;

            dgt_schar client_ip[65];
            dgt_schar client_mac[65];
            memset(client_ip, 0, 65);
            memset(client_mac, 0, 65);
#ifdef WIN32
            if (ip) strncpy(client_ip, ip, 64);
            if (mac) strncpy(client_mac, mac, 64);
#else
            PcLoginIpProber plip;
            PcLoginIpProber plmac;
            if ((ip == 0 || *ip == 0 || strncmp(ip, "127.0.0.1", 9) == 0) &&
                *KeySvrSessionPool->ipProbCmdPath()) {
                //
                // beq session, need to obtain login IP
                //
                plip.getLoginIp(KeySvrSessionPool->ipProbCmdPath(),
                                KeySvrSessionPool->ipProbCmdArgs(),
                                KeySvrSessionPool->ipProbPos(), client_ip);
            } else if (ip) {
                strncpy(client_ip, ip, 64);
            }
            if (PcaKeySvrSessionPool::traceLevel() > 0)
                PcaKeySvrSessionPool::logging("SID[%d]:: get IP => [%s]", SID,
                                              client_ip);

            if ((mac == 0 || *mac == 0 || strlen(mac) == 0) &&
                *KeySvrSessionPool->macProbCmdPath()) {
                //
                // get client mac
                //
                plmac.getMac4Ip(KeySvrSessionPool->macProbCmdPath(),
                                KeySvrSessionPool->macProbCmdArgs(),
                                KeySvrSessionPool->macProbIpPos(), client_ip,
                                KeySvrSessionPool->macProbPos(), client_mac);
                if (PcaKeySvrSessionPool::traceLevel() > 0)
                    PcaKeySvrSessionPool::logging(
                        "SID[%d]:: get mac => [%s][%s]", SID, client_ip,
                        client_mac);
            } else if (mac) {
                strncpy(client_mac, mac, 64);
            }
#endif
            if (instance_name == 0 || *instance_name == 0)
                instance_name = KeySvrSessionPool->instanceName();
            if (db_name == 0 || *db_name == 0)
                db_name = KeySvrSessionPool->dbName();

            pc_type_open_sess_out sess_out;
            memset(&sess_out, 0, sizeof(pc_type_open_sess_out));
            if ((ErrCode = svr_session->openSession(
                     db_sid, instance_name, db_name, client_ip, db_user,
                     os_user, program, protocol, user_id, client_mac,
                     &sess_out))) {
                PcaKeySvrSessionPool::logging(
                    "client[%s] open session failed:%d:%s.", client_ip, ErrCode,
                    svr_session->errMsg());
            }
            UserSID = sess_out.user_sid;
            AuthFailCode = sess_out.auth_fail_code;
            if (PcaKeySvrSessionPool::traceLevel() > 0)
                PcaKeySvrSessionPool::logging(
                    "SID[%d]:: openSession => UserSID[%lld]AuthFailCode[%d]",
                    SID, UserSID, AuthFailCode);
            KeySvrSessionPool->returnSession(svr_session);

            //
            // added by chchung, 2012.10.11
            //
            if (*SessInfo.client_ip == 0 && *SessInfo.user_id == 0 &&
                *SessInfo.client_program == 0 && *SessInfo.db_user == 0) {
                SessInfo.db_sid = db_sid;
                if (instance_name)
                    strncpy(SessInfo.instance_name, instance_name, 32);
                if (db_name) strncpy(SessInfo.db_name, db_name, 32);
                strncpy(SessInfo.client_ip, client_ip, 64);
                if (db_user) strncpy(SessInfo.db_user, db_user, 32);
                if (os_user) strncpy(SessInfo.os_user, os_user, 32);
                if (program) strncpy(SessInfo.client_program, program, 127);
                SessInfo.protocol = protocol;
                if (user_id) strncpy(SessInfo.user_id, user_id, 32);
                strncpy(SessInfo.client_mac, client_mac, 64);
            }
        }
        return ErrCode ? ErrCode : SID;
    };

    inline dgt_uint8 hasEncryptPriv(dgt_sint64 enc_col_id) {
        PcaPrivilege* priv = getPrivilege(enc_col_id);
        if (priv) return priv->getCryptPriv(PCI_CRYPT_OP_ENCRYPT);
        return 0;
    };

    inline dgt_uint8 hasDecryptPriv(dgt_sint64 enc_col_id) {
        PcaPrivilege* priv = getPrivilege(enc_col_id);
        if (priv) return priv->getCryptPriv(PCI_CRYPT_OP_DECRYPT);
        return 0;
    };

    inline dgt_uint8 isEncryptAudit(const dgt_schar* enc_col_name) {
        ErrCode = 0;
        dgt_sint64 enc_col_id = NamePool->getID(enc_col_name);
        if (enc_col_id < 0) {
            ErrCode = (dgt_sint32)enc_col_id;
            dgt_schar err_msg[129];
            sprintf(err_msg, "getID[%s] failed",
                    enc_col_name ? enc_col_name : "");
            PcaKeySvrSessionPool::logging(ErrCode, err_msg);
            return 0;
        }
        PcaPrivilege* priv = getPrivilege(enc_col_id);
        if (priv) return priv->isEncryptAudit();
        return 0;
    };

    inline dgt_uint8 isDecryptAudit(const dgt_schar* enc_col_name) {
        ErrCode = 0;
        dgt_sint64 enc_col_id = NamePool->getID(enc_col_name);
        if (enc_col_id < 0) {
            ErrCode = (dgt_sint32)enc_col_id;
            dgt_schar err_msg[129];
            sprintf(err_msg, "getID[%s] failed",
                    enc_col_name ? enc_col_name : "");
            PcaKeySvrSessionPool::logging(ErrCode, err_msg);
            return 0;
        }
        PcaPrivilege* priv = getPrivilege(enc_col_id);
        if (priv) return priv->isDecryptAudit();
        return 0;
    };

    inline dgt_sint64 maskingDecCount(const dgt_schar* enc_col_name) {
        ErrCode = 0;
        dgt_sint64 enc_col_id = NamePool->getID(enc_col_name);
        if (enc_col_id < 0) {
            ErrCode = (dgt_sint32)enc_col_id;
            dgt_schar err_msg[129];
            sprintf(err_msg, "getID[%s] failed",
                    enc_col_name ? enc_col_name : "");
            PcaKeySvrSessionPool::logging(ErrCode, err_msg);
            return 0;
        }
        PcaPrivilege* priv = getPrivilege(enc_col_id);
        if (priv) return priv->maskingThreshold();
        return 0;
    };

    inline dgt_sint32 encryptLength(dgt_sint64 enc_col_id, dgt_sint32 src_len) {
        ErrCode = 0;
        PcaPrivilege* priv = getPrivilege(enc_col_id);
        if (priv) return priv->encryptLength(src_len);
        return ErrCode;
    };

    inline dgt_sint32 encryptLength(const dgt_schar* enc_col_name,
                                    dgt_sint32 src_len) {
        ErrCode = 0;
        dgt_sint64 enc_col_id = NamePool->getID(enc_col_name);
        if (enc_col_id < 0) {
            ErrCode = (dgt_sint32)enc_col_id;
            dgt_schar err_msg[129];
            sprintf(err_msg, "getID[%s] failed",
                    enc_col_name ? enc_col_name : "");
            PcaKeySvrSessionPool::logging(ErrCode, err_msg);
            return ErrCode;
        }
        PcaPrivilege* priv = getPrivilege(enc_col_id);
        if (priv) return priv->encryptLength(src_len);
        return ErrCode;
    };

    inline dgt_sint32 encrypt(dgt_sint64 enc_col_id, dgt_uint8* src,
                              dgt_sint32 src_len, dgt_uint8* dst,
                              dgt_uint32* dst_len, dgt_sint32 sql_type = 0,
                              PcaPrivilege* priv = 0, dgt_uint8* set_key = 0,
                              dgt_uint8* set_iv = 0,
                              dgt_schar* header_flag = (dgt_schar*)"off",
                              dgt_sint8 pad_type = 0)

    {
        ErrCode = 0;
#if 1  // added by chchung 2013.9.13 for adding test mode
        if (KeySvrSessionPool->opMode() >= PCI_OP_NO_PULL_NO_PUSH) {
            if (*dst_len > (dgt_uint32)src_len) *dst_len = src_len;
            memcpy(dst, src, *dst_len);
            return 0;
        }
#endif
        setNewSqlFlag();  // decide whether this call's the first from a new sql
        PcaKeySvrSession* svr_session = 0;
        if (priv == 0) priv = getPrivilege(enc_col_id);
        if (priv && AuthFailCode &&
            priv->authFailEncPriv() > PCI_ENCRYPT_PRIV) {
            //
            // Authentaication fail
            //
            //
            // if AuditFlag > 0 the setting the NewSqlInterval = 200000
            //
            if (KeySvrSessionPool->newSqlInterval() == 0 &&
                (priv->encAuditFlag() || priv->decAuditFlag())) {
                KeySvrSessionPool->setNewSqlInterval(200000);
            }
            ErrCode = PcaPrivilege::PK_NO_ENCRYPT_PRIV;
            //
            // Posting the ErrMsg
#if 0
			if (svr_session || KeySvrSessionPool->getSession(&svr_session) == 0) {
				dgt_sint32 svr_err_code=0;
				if ((svr_err_code=svr_session->posting(UserSID, enc_col_id, ErrCode))) {
					PcaKeySvrSessionPool::logging(svr_err_code, svr_session->errMsg());
				}
				if (svr_session) KeySvrSessionPool->returnSession(svr_session);
			}
#endif
            return ErrCode == 0 ? NewSqlFlag : ErrCode;
        }
        if (priv) {
            //
            // Authentaication success
            //
            //
            // if AuditFlag > 0 the setting the NewSqlInterval = 200000
            //
            if (KeySvrSessionPool->newSqlInterval() == 0 &&
                KeySvrSessionPool->apiMode() == 0 &&
                (priv->encAuditFlag() || priv->decAuditFlag())) {
                KeySvrSessionPool->setNewSqlInterval(200000);
            }
            if (priv->getCryptPriv(PCI_CRYPT_OP_ENCRYPT, sql_type) <=
                PCI_ENCRYPT_PRIV) {  // encryption privilege check
                //
                // charater set conversion
                //
#ifdef WIN32
                dgt_sint32 rtn = 0;
#else
                dgt_sint32 rtn = convCharSet((dgt_schar*)src, src_len, priv);
#endif
                if (rtn >= 0) {
                    if (rtn > 0) {  // converted and the result size is rtn
                        src = ConvBuffer;
                        src_len = rtn;
                    }
#if 1  // modified by chchung 2013.9.13 for adding test mode
                    if (KeySvrSessionPool->opMode() || priv->opMode()) {
                        dgt_uint32 tmp_dst_len = *dst_len;
                        if (KeySvrSessionPool->isEncryptLocal()) {
                            // delegate decision of enforcing the same load to
                            // PcaPrivilege because PcaPrivilege has key
                            // fetching routine.
                            priv->encrypt(
                                src, src_len, dst, &tmp_dst_len,
                                (strncmp(header_flag, "on", 2) == 0)
                                    ? 0
                                    : KeySvrSessionPool->doubleEncCheck(),
                                0, set_key, set_iv, pad_type);
                        } else {
                            if (svr_session || KeySvrSessionPool->getSession(
                                                   &svr_session) == 0) {
                                if (KeySvrSessionPool->opMode() ==
                                        PCI_OP_NO_CRYPT_EQUAL_LOAD ||
                                    (KeySvrSessionPool->opMode() == 0 &&
                                     priv->opMode())) {
                                    // the same load
                                    if ((ErrCode = svr_session->encrypt(
                                             enc_col_id, src, src_len, dst,
                                             &tmp_dst_len))) {
                                        PcaKeySvrSessionPool::logging(
                                            ErrCode, svr_session->errMsg());
                                    }
                                }
                                if (svr_session)
                                    KeySvrSessionPool->returnSession(
                                        svr_session);
                            }
                        }
                        memset(dst, 0, tmp_dst_len);
                        if (*dst_len > (dgt_uint32)src_len) *dst_len = src_len;
                        memcpy(dst, src, *dst_len);
                        return ErrCode = 0;
                    } else {
                        if (KeySvrSessionPool->isEncryptLocal()) {
                            ErrCode = priv->encrypt(
                                src, src_len, dst, dst_len,
                                (strncmp(header_flag, "on", 2) == 0)
                                    ? 0
                                    : KeySvrSessionPool->doubleEncCheck(),
                                0, set_key, set_iv, pad_type);
                        } else {
                            if (svr_session || KeySvrSessionPool->getSession(
                                                   &svr_session) == 0) {
                                if ((ErrCode = svr_session->encrypt(
                                         enc_col_id, src, src_len, dst,
                                         dst_len))) {
                                    PcaKeySvrSessionPool::logging(
                                        ErrCode, svr_session->errMsg());
                                }
                                if (svr_session)
                                    KeySvrSessionPool->returnSession(
                                        svr_session);
                            }
                        }
                    }
#else
                    if (KeySvrSessionPool->isEncryptLocal()) {
                        ErrCode =
                            priv->encrypt(src, src_len, dst, dst_len,
                                          KeySvrSessionPool->doubleEncCheck(),
                                          0, set_key, set_iv);
                    } else {
                        if (svr_session ||
                            KeySvrSessionPool->getSession(&svr_session) == 0) {
                            if ((ErrCode = svr_session->encrypt(
                                     enc_col_id, src, src_len, dst, dst_len))) {
                                PcaKeySvrSessionPool::logging(
                                    ErrCode, svr_session->errMsg());
                            }
                            if (svr_session)
                                KeySvrSessionPool->returnSession(svr_session);
                        }
                    }
#endif
                }
            } else {
                ErrCode = PcaPrivilege::PK_NO_ENCRYPT_PRIV;
                if (priv->encCount() == 1) {
                    priv->setEncLogPriv(PCI_ENCRYPT_PRIV_ERR);
                    //
                    // in case of no privilege & first try, need to check
                    // alerting rule
                    //
                    if (priv->isEncryptAlert()) {
                        if (svr_session ||
                            KeySvrSessionPool->getSession(&svr_session) == 0) {
                            setAlertRequest(enc_col_id, 0, 0,
                                            PS_NO_PRIV_ENCRYPT_ALERT);
                            if (svr_session->alert(&AlertRequest)) {
                                PcaKeySvrSessionPool::logging(
                                    ErrCode, svr_session->errMsg());
                            }
                            if (svr_session)
                                KeySvrSessionPool->returnSession(svr_session);
                            if (PcaKeySvrSessionPool::traceLevel() > 0)
                                PcaKeySvrSessionPool::logging(
                                    "SID[%d]:: no priv encrypt alert => [%d]",
                                    SID, ErrCode);
                        }
                    }
                }
            }
        }
        //
        // request reset
        //
#if 0
		if (KeySvrSessionPool->newSqlInterval()) {
			gettimeofday(&LastCallTime,0); // to exclude the time period spent on this function job
		}
#endif

        if (ErrCode != 0) {
            //
            // Posting the ErrMsg
            //
#if 0
			dgt_sint32 svr_err_code=0;
                        if (svr_session || KeySvrSessionPool->getSession(&svr_session) == 0) {
                        	if ((svr_err_code=svr_session->posting(UserSID, enc_col_id, ErrCode))) {
					PcaKeySvrSessionPool::logging(svr_err_code, svr_session->errMsg());
				}
				if (svr_session) KeySvrSessionPool->returnSession(svr_session);
			}
#endif
        }
        if (priv) {
            // charset Conversion for ibk requirement
            // in case encrypting part of multibyte data
#ifdef WIN32
            dgt_sint32 rtn = 0;
#else
            dgt_sint32 rtn =
                convCharSet((dgt_schar*)dst, (dgt_sint32)*dst_len, priv, 1);
#endif
            if (rtn > 0) {
                memcpy(dst, ConvBuffer, rtn);
                *dst_len = rtn;
            }
        }
#if 1  // modified by chchung 2017.6.20 for allowing optional decrypting error
       // handling
        if (ErrCode && KeySvrSessionPool->decryptFailSrcRtn() &&
            (strncmp(header_flag, "on", 2) != 0)) {
            if (ErrCode == PCI_ERR_ALREADY_ENCRYPTED) {
                memcpy(dst, src, src_len);
            } else {
                *dst_len = src_len;
                memcpy(dst, src, src_len);
            }
            ErrCode = 0;
        }
#else
        if (ErrCode != 0) {
            *dst_len = src_len;
            memcpy(dst, src, src_len);
            ErrCode = 0;
        }
#endif
        return ErrCode == 0 ? NewSqlFlag : ErrCode;
    };

    inline dgt_sint32 encrypt(dgt_sint64 enc_col_id, dgt_uint8* src,
                              dgt_sint32 src_len, dgt_uint8** dst,
                              dgt_uint32* dst_len, dgt_sint32 sql_type = 0) {
        ErrCode = 0;
#if 1  // added by chchung 2013.9.13 for adding test mode
        if (KeySvrSessionPool->opMode() >= PCI_OP_NO_PULL_NO_PUSH) {
            *dst_len = extendOutBuffer(src_len);
            *dst = OutBuffer;
            encrypt(enc_col_id, src, src_len, OutBuffer, dst_len, sql_type);
            return 0;
        }
#endif
        PcaPrivilege* priv =
            getPrivilege(enc_col_id);  // get a for "enc_col_id"
        if (priv) {
            *dst_len = 4000;
            if (OutBufferLength == 0) {
                delete OutBuffer;
                OutBuffer = new dgt_uint8[OutBufferLength = 4000];
            }
            if (src_len > 2000) {
                if (priv->ophFlag()) {
                    *dst_len =
                        4 * (dgt_sint32)ceil((double)(src_len + 64) / 3) + 32 +
                        priv->ophLength();
                } else {
                    *dst_len =
                        4 * (dgt_sint32)ceil((double)(src_len + 64) / 3) + 32;
                }
                if (*dst_len > OutBufferLength) {
                    delete OutBuffer;
                    OutBuffer = new dgt_uint8[OutBufferLength = *dst_len];
                    if (PcaKeySvrSessionPool::traceLevel() > 0)
                        PcaKeySvrSessionPool::logging(
                            "SID[%d]:: OutBuffer[%d] replaced", SID,
                            OutBufferLength);
                }
            }
            *dst = OutBuffer;
            encrypt(enc_col_id, src, src_len, OutBuffer, dst_len, sql_type,
                    priv);
        }
        return ErrCode == 0 ? NewSqlFlag : ErrCode;
    };

    inline dgt_sint32 encrypt(const dgt_schar* enc_col_name, dgt_uint8* src,
                              dgt_sint32 src_len, dgt_uint8* dst,
                              dgt_uint32* dst_len, dgt_sint32 sql_type = 0,
                              dgt_uint8* set_key = 0, dgt_uint8* set_iv = 0,
                              dgt_uint8 pad_type = 0) {
        ErrCode = 0;
#if 1  // added by chchung 2013.9.13 for adding test mode
        if (KeySvrSessionPool->opMode() >= PCI_OP_NO_PULL_NO_PUSH) {
            if (*dst_len > (dgt_uint32)src_len) *dst_len = src_len;
            memcpy(dst, src, *dst_len);
            return 0;
        }
#endif
        dgt_sint64 enc_col_id = NamePool->getID(enc_col_name);
        if (enc_col_id < 0) {
            ErrCode = (dgt_sint32)enc_col_id;
            dgt_schar err_msg[129];
            sprintf(err_msg, "getID[%s] failed",
                    enc_col_name ? enc_col_name : "");
            PcaKeySvrSessionPool::logging(ErrCode, err_msg);
        } else {
            encrypt(enc_col_id, src, src_len, dst, dst_len, sql_type, 0,
                    set_key, set_iv, (dgt_schar*)"off", pad_type);
        }
        return ErrCode == 0 ? NewSqlFlag : ErrCode;
    };

    inline dgt_sint32 encrypt(const dgt_schar* enc_col_name, dgt_uint8* src,
                              dgt_sint32 src_len, dgt_uint8** dst,
                              dgt_uint32* dst_len, dgt_sint32 sql_type = 0,
                              dgt_uint8* set_key = 0, dgt_uint8* set_iv = 0,
                              dgt_uint8 pad_type = 0) {
        ErrCode = 0;
#if 1  // added by chchung 2013.9.13 for adding test mode
        if (KeySvrSessionPool->opMode() >= PCI_OP_NO_PULL_NO_PUSH) {
            *dst_len = extendOutBuffer(src_len);
            *dst = OutBuffer;
            encrypt(enc_col_name, src, src_len, OutBuffer, dst_len, sql_type);
            return 0;
        }
#endif
        dgt_sint64 enc_col_id = NamePool->getID(enc_col_name);
        if (enc_col_id < 0) {
            ErrCode = (dgt_sint32)enc_col_id;
            dgt_schar err_msg[129];
            sprintf(err_msg, "getID[%s] failed",
                    enc_col_name ? enc_col_name : "");
            PcaKeySvrSessionPool::logging(ErrCode, err_msg);
        } else {
            PcaPrivilege* priv =
                getPrivilege(enc_col_id);  // get a for "enc_col_id"
            if (priv) {
                *dst_len = 4000;
                if (OutBufferLength == 0) {
                    delete OutBuffer;
                    OutBuffer = new dgt_uint8[OutBufferLength = 4000];
                }
                if (src_len > 2000) {
                    if (priv->ophFlag()) {
                        *dst_len =
                            4 * (dgt_sint32)ceil((double)(src_len + 64) / 3) +
                            32 + priv->ophLength();
                    } else {
                        *dst_len =
                            4 * (dgt_sint32)ceil((double)(src_len + 64) / 3) +
                            32;
                    }
                    if (*dst_len > OutBufferLength) {
                        delete OutBuffer;
                        OutBuffer = new dgt_uint8[OutBufferLength = *dst_len];
                        if (PcaKeySvrSessionPool::traceLevel() > 0)
                            PcaKeySvrSessionPool::logging(
                                "SID[%d]:: OutBuffer[%d] replaced", SID,
                                OutBufferLength);
                    }
                }
                *dst = OutBuffer;
                encrypt(enc_col_id, src, src_len, OutBuffer, dst_len, sql_type,
                        priv, set_key, set_iv, (dgt_schar*)"off", pad_type);
            }
        }
        return ErrCode == 0 ? NewSqlFlag : ErrCode;
    };

    inline dgt_sint32 encrypt(const dgt_schar* enc_col_name, dgt_uint8* src,
                              dgt_sint32 src_len, dgt_uint8* dst,
                              dgt_uint32* dst_len, dgt_schar* header_flag) {
        ErrCode = 0;
#if 1  // added by chchung 2013.9.13 for adding test mode
        if (KeySvrSessionPool->opMode() >= PCI_OP_NO_PULL_NO_PUSH) {
            if (*dst_len > (dgt_uint32)src_len) *dst_len = src_len;
            memcpy(dst, src, *dst_len);
            return 0;
        }
#endif
        dgt_sint64 enc_col_id = NamePool->getID(enc_col_name);
        if (enc_col_id < 0) {
            ErrCode = (dgt_sint32)enc_col_id;
            dgt_schar err_msg[129];
            sprintf(err_msg, "getID[%s] failed",
                    enc_col_name ? enc_col_name : "");
            PcaKeySvrSessionPool::logging(ErrCode, err_msg);
        } else {
            encrypt(enc_col_id, src, src_len, dst, dst_len, 0, 0, 0, 0,
                    header_flag);
        }
        return ErrCode == 0 ? NewSqlFlag : ErrCode;
    }

    inline dgt_sint32 crypt_test(dgt_sint64 enc_col_id, dgt_uint8* src,
                                 dgt_sint32 ksv_num) {
        dgt_sint32 src_len = strlen((const dgt_schar*)src);
        dgt_schar enc[10000] = {
            0,
        };
        dgt_uint32 enc_len = 10000;
        dgt_schar dec[10000] = {
            0,
        };
        dgt_uint32 dec_len = 10000;

        ErrCode = 0;
        PcaKeySvrSession* svr_session = 0;
        PcaPrivilege* priv = getPrivilege(enc_col_id);
        if (!priv) return 1;  // enc_col_id not found.

            //
            // charater set conversion
            //
#ifdef WIN32
        dgt_sint32 rtn = 0;
#else
        dgt_sint32 rtn = convCharSet((dgt_schar*)src, src_len, priv);
#endif
        if (rtn >= 0) {
            if (rtn > 0) {  // converted and the result size is rtn
                src = ConvBuffer;
                src_len = rtn;
            }
            if (KeySvrSessionPool->getSession(&svr_session) != 0)
                return 2;  // key server not found.

            // encrypt
            if ((ErrCode = svr_session->encrypt(enc_col_id, src, src_len,
                                                (dgt_uint8*)enc, &enc_len,
                                                ksv_num))) {
                PcaKeySvrSessionPool::logging(ErrCode, svr_session->errMsg());
                if (svr_session) KeySvrSessionPool->returnSession(svr_session);
                return ErrCode;
            }
            // decrypt
            if ((ErrCode = svr_session->decrypt(enc_col_id, (dgt_uint8*)enc,
                                                enc_len, (dgt_uint8*)dec,
                                                &dec_len, ksv_num))) {
                PcaKeySvrSessionPool::logging(ErrCode, svr_session->errMsg());
                if (svr_session) KeySvrSessionPool->returnSession(svr_session);
                return ErrCode;
            }
            // diff
            if (svr_session) KeySvrSessionPool->returnSession(svr_session);
            if (strcmp((const dgt_schar*)src, (const dgt_schar*)dec))
                return 3;  // src & dec are different
        }
        return 0;  // success
    };

    inline dgt_sint32 crypt_test(const dgt_schar* enc_col_name, dgt_uint8* src,
                                 dgt_sint32 ksv_num) {
        ErrCode = 0;
        dgt_sint64 enc_col_id = NamePool->getID(enc_col_name);
        if (enc_col_id < 0) {
            ErrCode = (dgt_sint32)enc_col_id;
            dgt_schar err_msg[129];
            sprintf(err_msg, "getID[%s] failed",
                    enc_col_name ? enc_col_name : "");
            PcaKeySvrSessionPool::logging(ErrCode, err_msg);
        } else {
            ErrCode = crypt_test(enc_col_id, src, ksv_num);
        }
        return ErrCode;
    };

    inline dgt_sint32 decrypt(dgt_sint64 enc_col_id, dgt_uint8* src,
                              dgt_sint32 src_len, dgt_uint8* dst,
                              dgt_uint32* dst_len, dgt_sint32 sql_type = 0,
                              PcaPrivilege* priv = 0, dgt_uint8* set_key = 0,
                              dgt_uint8* set_iv = 0,
                              dgt_schar* header_flag = (dgt_schar*)"off",
                              dgt_uint8 pad_type = 0) {
        ErrCode = 0;
#if 1  // added by chchung 2013.9.13 for adding test mode
        if (KeySvrSessionPool->opMode() >= PCI_OP_NO_PULL_NO_PUSH) {
            if (*dst_len > (dgt_uint32)src_len) *dst_len = src_len;
            memcpy(dst, src, *dst_len);
            return 0;
        }
#endif
        setNewSqlFlag();
        if (priv == 0) priv = getPrivilege(enc_col_id);

        if (priv) {
            // charset Conversion for ibk requirement
            // in case encrypting part of multibyte data
#ifdef WIN32
            dgt_sint32 rtn = 0;
#else
            dgt_sint32 rtn = convCharSet((dgt_schar*)src, src_len, priv);
#endif
            if (rtn >= 0) {
                if (rtn > 0) {  // converted and the result size is rtn
                    src = ConvBuffer;
                    src_len = rtn;
                }
            }
        }

        if (priv && AuthFailCode &&
            priv->authFailDecPriv() > PCI_DEC_PRIV_DEC) {
            //
            // Authentaication fail
            //
            //
            // if AuditFlag > 0 the setting the NewSqlInterval = 200000
            //
            if (KeySvrSessionPool->newSqlInterval() == 0 &&
                KeySvrSessionPool->apiMode() == 0 &&
                (priv->encAuditFlag() || priv->decAuditFlag())) {
                KeySvrSessionPool->setNewSqlInterval(200000);
            }
            PcaKeySvrSession* svr_session = 0;
            if (priv->authFailDecPriv() == PCI_DEC_PRIV_MASK) {
                //
                // masking or
                // decrypt allowed,
                // which session has decryption privilege & no approve rule or
                // approved as "PCI_DEC_PRIV_DEC". the decLogPrivFlag() returns
                // "PCI_DEC_PRIV_DEC" if there's no settig, because
                // decLogPrivFlag was initialized as "PCI_DEC_PRIV_DEC"
                //
                dgt_uint32 dst_buf_len = *dst_len;
#if 1  // modified by chchung 2013.9.13 for adding test mode
                if (KeySvrSessionPool->opMode() || priv->opMode()) {
                    if (KeySvrSessionPool->isDecryptLocal()) {
                        // delegate decision of enforcing the same load to
                        // PcaPrivilege
                        priv->encrypt(src, src_len, dst, &dst_buf_len);
                    } else {
                        if (svr_session ||
                            KeySvrSessionPool->getSession(&svr_session) == 0) {
                            if (KeySvrSessionPool->opMode() ==
                                    PCI_OP_NO_CRYPT_EQUAL_LOAD ||
                                (KeySvrSessionPool->opMode() == 0 &&
                                 priv->opMode())) {
                                // the same load
                                if ((ErrCode = svr_session->encrypt(
                                         enc_col_id, src, src_len, dst,
                                         &dst_buf_len))) {
                                    PcaKeySvrSessionPool::logging(
                                        ErrCode, svr_session->errMsg());
                                }
                            }
                            if (svr_session)
                                KeySvrSessionPool->returnSession(svr_session);
                        }
                    }
                    memset(dst, 0, dst_buf_len);
                    if (*dst_len > (dgt_uint32)src_len) *dst_len = src_len;
                    memcpy(dst, src, *dst_len);
                    return ErrCode = 0;
                } else {
                    if (KeySvrSessionPool->isDecryptLocal()) {
                        ErrCode = priv->decrypt(
                            src, src_len, dst, dst_len, set_key, set_iv,
                            (strncmp(header_flag, "on", 2) == 0)
                                ? 0
                                : KeySvrSessionPool->decryptFailSrcRtn(),
                            pad_type);
                    } else {
                        if (svr_session ||
                            KeySvrSessionPool->getSession(&svr_session) == 0) {
                            if ((ErrCode = svr_session->decrypt(
                                     enc_col_id, src, src_len, dst, dst_len))) {
                                PcaKeySvrSessionPool::logging(
                                    ErrCode, svr_session->errMsg());
                            }
                            if (svr_session)
                                KeySvrSessionPool->returnSession(svr_session);
                        }
                    }
                }
#else
                if (KeySvrSessionPool->isDecryptLocal()) {
                    ErrCode = priv->decrypt(
                        src, src_len, dst, dst_len, set_key, set_iv,
                        KeySvrSessionPool->decryptFailSrcRtn());
                } else {
                    if (svr_session ||
                        KeySvrSessionPool->getSession(&svr_session) == 0) {
                        if ((ErrCode = svr_session->decrypt(
                                 enc_col_id, src, src_len, dst, dst_len))) {
                            PcaKeySvrSessionPool::logging(
                                ErrCode, svr_session->errMsg());
                        }
                        if (svr_session)
                            KeySvrSessionPool->returnSession(svr_session);
                    }
                }
#endif
                if (ErrCode == 0) {
                    //
                    // charater set conversion for decrypted data
                    //
#ifdef WIN32
                    dgt_sint32 rtn = 0;
#else
                    dgt_sint32 rtn = convCharSet((dgt_schar*)dst,
                                                 (dgt_sint32)*dst_len, priv, 1);
#endif
                    if (rtn > 0) {
                        //
                        // converted and the result size is rtn
                        //
                        if (rtn > (dgt_sint32)dst_buf_len) {
                            ErrCode = PCI_ERR_OUT_BUFFER_TOO_SHORT;
                        } else {
                            memcpy(dst, ConvBuffer, rtn);
                            *dst_len = rtn;
                        }
                    }
                }
            }
            if (ErrCode == 0) {
                //
                // in case of no error while calling previous functions,
                //
                if (priv->authFailDecPriv() > PCI_DEC_PRIV_DEC) {
                    //
                    // no error and no privilege
                    //
                    if (priv->authFailDecPriv() ==
                        PCI_DEC_PRIV_ERR) {  // error return
                        ErrCode = PcaPrivilege::PK_NO_DECRYPT_PRIV;
                    } else if (priv->authFailDecPriv() ==
                               PCI_DEC_PRIV_SRC) {  // encrypted data return
                        //
                        // limited data (MaxColLen)
                        //
                        if (src_len > priv->maxColLength()) {
                            *dst_len = priv->maxColLength();
                            memcpy(dst, src, *dst_len);
                        } else {
                            *dst_len = src_len;
                            memcpy(dst, src, *dst_len);
                        }
                    } else {
                        //
                        // masking in which case the "dst" data has been
                        // decrypted already.
                        //
                        dgt_uint32 masking_len = priv->maskingLength(*dst_len);
                        if (priv->colType() == PCI_SRC_TYPE_NUM) {
                            if (masking_len > 0) {
                                dgt_uint8* cp =
                                    dst + priv->encStartPos(*dst_len) - 1;
                                memset(cp, PS_DFLT_MASK_NUM, masking_len);
                            }
                        } else if (priv->colType() == PCI_SRC_TYPE_DATE) {
                            if (masking_len > 0) {
                                dgt_uint8* cp =
                                    dst + priv->encStartPos(*dst_len) - 1;
                                memset(cp, 0, masking_len);
                                dgt_schar mask_char[15];
                                memset(mask_char, 0, 15);
                                sprintf(mask_char, "01010101010101");
                                memcpy(cp, mask_char, strlen(mask_char));
                            }
                        } else {
                            if (masking_len > 0) {
                                dgt_uint8* cp =
                                    dst + priv->encStartPos(*dst_len) - 1;
                                dgt_uint32 mask_pttn_len =
                                    strlen(priv->maskChar());
                                if (mask_pttn_len == 0) {
                                    memset(cp, PS_DFLT_MASK_CHAR, masking_len);
                                } else {
                                    while (masking_len > 0) {
                                        if (masking_len <= mask_pttn_len) {
                                            memcpy(cp, priv->maskChar(),
                                                   masking_len);
                                            masking_len = 0;
                                        } else {
                                            memcpy(cp, priv->maskChar(),
                                                   mask_pttn_len);
                                            masking_len -= mask_pttn_len;
                                            cp += mask_pttn_len;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
#if 0
                	if (KeySvrSessionPool->newSqlInterval()) {
                        	gettimeofday(&LastCallTime,0);
	                }
#endif
#if 1  // modified by chchung 2017.6.20 for allowing optional decrypting error
       // handling
            if (ErrCode && KeySvrSessionPool->decryptFailSrcRtn() &&
                (strncmp(header_flag, "on", 2) != 0)) {
                //*dst_len = src_len;
                memcpy(dst, src, src_len);
                ErrCode = 0;
            }
#else
            if (ErrCode != 0) {
                *dst_len = src_len;
                memcpy(dst, src, src_len);
                ErrCode = 0;
            }
#endif
            return ErrCode == 0 ? NewSqlFlag : ErrCode;
        }
        //
        // Authentcation success
        //
        if (priv) {
            //
            // if AuditFlag > 0 the setting the NewSqlInterval = 200000
            //
            if (KeySvrSessionPool->newSqlInterval() == 0 &&
                KeySvrSessionPool->apiMode() == 0 &&
                (priv->encAuditFlag() || priv->decAuditFlag())) {
                KeySvrSessionPool->setNewSqlInterval(200000);
            }
            PcaKeySvrSession* svr_session = 0;
            dgt_uint8 dec_priv;
            if ((dec_priv = priv->getCryptPriv(PCI_CRYPT_OP_DECRYPT,
                                               sql_type)) <= PCI_DEC_PRIV_DEC) {
                //
                // session has decryption privilege,
                // so check Masking rule
                //
                if (priv->isMasking()) {
                    priv->setDecLogPriv((dgt_uint8)PCI_DEC_PRIV_MASK);
                }
            } else {
                priv->setDecLogPriv(dec_priv);
            }
            if (priv->decLogPrivFlag() <= PCI_DEC_PRIV_DEC ||
                priv->decLogPrivFlag() == PCI_DEC_PRIV_MASK) {
                //
                // masking or
                // decrypt allowed,
                // which session has decryption privilege & no approve rule or
                // approved as "PCI_DEC_PRIV_DEC". the decLogPrivFlag() returns
                // "PCI_DEC_PRIV_DEC" if there's no settig, because
                // decLogPrivFlag was initialized as "PCI_DEC_PRIV_DEC"
                //
                dgt_uint32 dst_buf_len = *dst_len;
#if 1  // added by chchung 2013.9.13 for adding test mode
                if (KeySvrSessionPool->opMode() || priv->opMode()) {
                    if (KeySvrSessionPool->isDecryptLocal()) {
                        priv->encrypt(src, src_len, dst, &dst_buf_len);
                    } else {
                        if (svr_session ||
                            KeySvrSessionPool->getSession(&svr_session) == 0) {
                            if (KeySvrSessionPool->opMode() ==
                                    PCI_OP_NO_CRYPT_EQUAL_LOAD ||
                                (KeySvrSessionPool->opMode() == 0 &&
                                 priv->opMode())) {
                                if ((ErrCode = svr_session->encrypt(
                                         enc_col_id, src, src_len, dst,
                                         &dst_buf_len))) {
                                    PcaKeySvrSessionPool::logging(
                                        ErrCode, svr_session->errMsg());
                                }
                            }
                            if (svr_session)
                                KeySvrSessionPool->returnSession(svr_session);
                        }
                    }
                    memset(dst, 0, dst_buf_len);
                    if (*dst_len > (dgt_uint32)src_len) *dst_len = src_len;
                    memcpy(dst, src, *dst_len);
                    return ErrCode = 0;
                } else {
                    if (KeySvrSessionPool->isDecryptLocal()) {
                        ErrCode = priv->decrypt(
                            src, src_len, dst, dst_len, set_key, set_iv,
                            (strncmp(header_flag, "on", 2) == 0)
                                ? 0
                                : KeySvrSessionPool->decryptFailSrcRtn(),
                            pad_type);
                    } else {
                        if (svr_session ||
                            KeySvrSessionPool->getSession(&svr_session) == 0) {
                            if ((ErrCode = svr_session->decrypt(
                                     enc_col_id, src, src_len, dst, dst_len))) {
                                PcaKeySvrSessionPool::logging(
                                    ErrCode, svr_session->errMsg());
                            }
                            if (svr_session)
                                KeySvrSessionPool->returnSession(svr_session);
                        }
                    }
                }
#else
                if (KeySvrSessionPool->isDecryptLocal()) {
                    ErrCode = priv->decrypt(
                        src, src_len, dst, dst_len, set_key, set_iv,
                        KeySvrSessionPool->decryptFailSrcRtn());
                } else {
                    if (svr_session ||
                        KeySvrSessionPool->getSession(&svr_session) == 0) {
                        if ((ErrCode = svr_session->decrypt(
                                 enc_col_id, src, src_len, dst, dst_len))) {
                            PcaKeySvrSessionPool::logging(
                                ErrCode, svr_session->errMsg());
                        }
                        if (svr_session)
                            KeySvrSessionPool->returnSession(svr_session);
                    }
                }
#endif
                if (ErrCode == 0) {
                    //
                    // charater set conversion for decrypted data
                    //
#ifdef WIN32
                    dgt_sint32 rtn = 0;
#else
                    dgt_sint32 rtn = convCharSet((dgt_schar*)dst,
                                                 (dgt_sint32)*dst_len, priv, 1);
#endif
                    if (rtn > 0) {
                        //
                        // converted and the result size is rtn
                        //
                        if (rtn > (dgt_sint32)dst_buf_len) {
                            ErrCode = PCI_ERR_OUT_BUFFER_TOO_SHORT;
                        } else {
                            memcpy(dst, ConvBuffer, rtn);
                            *dst_len = rtn;
                        }
                    }
                }
                dgt_sint32 rtn = priv->isAlert();
                if (rtn == 1) {
                    //
                    // decryption not allowed but too many decryption try so as
                    // to alert this event
                    //
                    AlertSqlFlag = 0;
                    setAlertRequest(enc_col_id, priv->alertDecCount(), 2,
                                    PS_TOO_MANY_DECRYPT_ALERT);
                    if (svr_session ||
                        KeySvrSessionPool->getSession(&svr_session) == 0) {
                        if ((ErrCode = svr_session->alert(&AlertRequest))) {
                            PcaKeySvrSessionPool::logging(
                                ErrCode, svr_session->errMsg());
                        }
                        if (svr_session)
                            KeySvrSessionPool->returnSession(svr_session);
                        if (PcaKeySvrSessionPool::traceLevel() > 0)
                            PcaKeySvrSessionPool::logging(
                                "SID[%d]:: too many[%u] not allowed decrypt "
                                "alert => ErrCode[%d]",
                                SID, priv->alertDecCount(), ErrCode);
                    }
                } else if (rtn < 0) {
                    AlertSqlFlag = 1;
                }
            }
            if (priv->decCount() == 1 &&
                priv->decLogPrivFlag() > PCI_DEC_PRIV_DEC &&
                priv->isDecryptAlert()) {
                //
                // in case of first descryption try without privilege,
                // need to check whether to send no-privilege-decryption-try
                // alert, alert for a decryption try without privilege.
                //
                if (svr_session ||
                    KeySvrSessionPool->getSession(&svr_session) == 0) {
                    setAlertRequest(enc_col_id, 0, 2, PS_NO_PRIV_DECRYPT_ALERT);
                    if (svr_session->alert(&AlertRequest)) {
                        PcaKeySvrSessionPool::logging(ErrCode,
                                                      svr_session->errMsg());
                    }
                    if (svr_session)
                        KeySvrSessionPool->returnSession(svr_session);
                    if (PcaKeySvrSessionPool::traceLevel() > 0)
                        PcaKeySvrSessionPool::logging(
                            "SID[%d]:: decrypt no priv alert[%lld] => "
                            "ErrCode[%d]",
                            SID, enc_col_id, ErrCode);
                }
            }
            if (ErrCode == 0) {
                //
                // in case of no error while calling previous functions,
                //
                dgt_sint32 rtn = 0;
                if (priv->decLogPrivFlag() > PCI_DEC_PRIV_DEC) {
                    //
                    // no error and no privilege
                    //
                    if (priv->decLogPrivFlag() ==
                        PCI_DEC_PRIV_ERR) {  // error return
                        ErrCode = PcaPrivilege::PK_NO_DECRYPT_PRIV;
                    } else if (priv->decLogPrivFlag() ==
                               PCI_DEC_PRIV_SRC) {  // encrypted data return
#if 0
						if (*dst_len > (dgt_uint32)src_len) *dst_len = src_len;
						memcpy(dst, src, *dst_len);
#endif
                        //
                        // limited data (MaxColLen)
                        //
                        if (src_len > priv->maxColLength()) {
                            *dst_len = priv->maxColLength();
                            memcpy(dst, src, *dst_len);
                        } else {
                            *dst_len = src_len;
                            memcpy(dst, src, *dst_len);
                        }
                    } else {
                        //
                        // masking in which case the "dst" data has been
                        // decrypted already.
                        //
                        dgt_uint32 masking_len = priv->maskingLength(*dst_len);
                        if (priv->colType() == PCI_SRC_TYPE_NUM) {
                            if (masking_len > 0) {
                                dgt_uint8* cp =
                                    dst + priv->encStartPos(*dst_len) - 1;
                                memset(cp, PS_DFLT_MASK_NUM, masking_len);
                            }
                        } else if (priv->colType() == PCI_SRC_TYPE_DATE) {
                            if (masking_len > 0) {
                                dgt_uint8* cp =
                                    dst + priv->encStartPos(*dst_len) - 1;
                                memset(cp, 0, masking_len);
                                dgt_schar mask_char[15];
                                memset(mask_char, 0, 15);
                                sprintf(mask_char, "01010101010101");
                                memcpy(cp, mask_char, strlen(mask_char));
                            }
                        } else {
                            if (masking_len > 0) {
                                dgt_uint8* cp =
                                    dst + priv->encStartPos(*dst_len) - 1;
                                dgt_uint32 mask_pttn_len =
                                    strlen(priv->maskChar());
                                if (mask_pttn_len == 0) {
                                    memset(cp, PS_DFLT_MASK_CHAR, masking_len);
                                } else {
                                    while (masking_len > 0) {
                                        if (masking_len <= mask_pttn_len) {
                                            memcpy(cp, priv->maskChar(),
                                                   masking_len);
                                            masking_len = 0;
                                        } else {
                                            memcpy(cp, priv->maskChar(),
                                                   mask_pttn_len);
                                            masking_len -= mask_pttn_len;
                                            cp += mask_pttn_len;
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else if ((rtn = priv->isAlert())) {
                    //
                    // decryption allowed but too many decryption try so as to
                    // alert this event
                    //
                    if (rtn < 0) {
                        AlertSqlFlag = 1;
                    } else {
                        AlertSqlFlag = 0;
                        setAlertRequest(enc_col_id, priv->alertDecCount(), 1,
                                        PS_TOO_MANY_DECRYPT_ALERT);
                        if (svr_session ||
                            KeySvrSessionPool->getSession(&svr_session) == 0) {
                            if ((ErrCode = svr_session->alert(&AlertRequest))) {
                                PcaKeySvrSessionPool::logging(
                                    ErrCode, svr_session->errMsg());
                            }
                            if (svr_session)
                                KeySvrSessionPool->returnSession(svr_session);
                            if (PcaKeySvrSessionPool::traceLevel() > 0)
                                PcaKeySvrSessionPool::logging(
                                    "SID[%d]:: too many[%u] decrypt alert => "
                                    "ErrCode[%d]",
                                    SID, priv->decCount(), ErrCode);
                        }
                    }
                }
            }
        }
#if 0
		if (KeySvrSessionPool->newSqlInterval()) {
			gettimeofday(&LastCallTime,0);
		}
#endif

#if 1  // modified by chchung 2017.6.20 for allowing optional decrypting error
       // handling
        if (ErrCode && KeySvrSessionPool->decryptFailSrcRtn() &&
            (strncmp(header_flag, "on", 2) != 0)) {
            //	               	*dst_len = src_len;
            memcpy(dst, src, src_len);
            ErrCode = 0;
        }
#else
        if (ErrCode != 0) {
            *dst_len = src_len;
            memcpy(dst, src, src_len);
            ErrCode = 0;
        }
#endif
        return ErrCode == 0 ? NewSqlFlag : ErrCode;
    };

    inline dgt_sint32 decrypt(dgt_sint64 enc_col_id, dgt_uint8* src,
                              dgt_sint32 src_len, dgt_uint8** dst,
                              dgt_uint32* dst_len, dgt_sint32 sql_type = 0) {
        ErrCode = 0;
#if 1  // added by chchung 2013.9.13 for adding test mode
        if (KeySvrSessionPool->opMode() >= PCI_OP_NO_PULL_NO_PUSH) {
            *dst_len = extendOutBuffer(src_len);
            *dst = OutBuffer;
            decrypt(enc_col_id, src, src_len, OutBuffer, dst_len, sql_type);
            return 0;
        }
#endif
        PcaPrivilege* priv = getPrivilege(enc_col_id);
        if (priv) {
            *dst_len = 4000;
            if (OutBufferLength == 0) {
                delete OutBuffer;
                OutBuffer = new dgt_uint8[OutBufferLength = 4000];
            }
            if (src_len > 2000) {
                *dst_len =
                    4 * (dgt_sint32)ceil((double)(src_len + 64) / 3) + 32;
                if (*dst_len > OutBufferLength) {
                    delete OutBuffer;
                    OutBuffer = new dgt_uint8[OutBufferLength = *dst_len];
                    if (PcaKeySvrSessionPool::traceLevel() > 0)
                        PcaKeySvrSessionPool::logging(
                            "SID[%d]:: OutBuffer[%d] replaced", SID,
                            OutBufferLength);
                }
            }
            *dst = OutBuffer;
            decrypt(enc_col_id, src, src_len, OutBuffer, dst_len, sql_type,
                    priv);
        }
        return ErrCode == 0 ? NewSqlFlag : ErrCode;
    };

    inline dgt_sint32 decrypt(const dgt_schar* enc_col_name, dgt_uint8* src,
                              dgt_sint32 src_len, dgt_uint8* dst,
                              dgt_uint32* dst_len, dgt_sint32 sql_type = 0,
                              dgt_uint8* set_key = 0, dgt_uint8* set_iv = 0,
                              dgt_uint8 pad_type = 0) {
        ErrCode = 0;
#if 1  // added by chchung 2013.9.13 for adding test mode
        if (KeySvrSessionPool->opMode() >= PCI_OP_NO_PULL_NO_PUSH) {
            if (*dst_len > (dgt_uint32)src_len) *dst_len = src_len;
            memcpy(dst, src, *dst_len);
            return 0;
        }
#endif
        dgt_sint64 enc_col_id = NamePool->getID(enc_col_name);
        if (enc_col_id < 0) {
            ErrCode = (dgt_sint32)enc_col_id;
            dgt_schar err_msg[129];
            sprintf(err_msg, "getID[%s] failed",
                    enc_col_name ? enc_col_name : "");
            PcaKeySvrSessionPool::logging(ErrCode, err_msg);
        } else {
            decrypt(enc_col_id, src, src_len, dst, dst_len, sql_type, 0,
                    set_key, set_iv, (dgt_schar*)"off", pad_type);
        }
        return ErrCode == 0 ? NewSqlFlag : ErrCode;
    };

    inline dgt_sint32 decrypt(const dgt_schar* enc_col_name, dgt_uint8* src,
                              dgt_sint32 src_len, dgt_uint8** dst,
                              dgt_uint32* dst_len, dgt_sint32 sql_type = 0,
                              dgt_uint8* set_key = 0, dgt_uint8* set_iv = 0,
                              dgt_sint8 pad_type = 0) {
        ErrCode = 0;
#if 1  // added by chchung 2013.9.13 for adding test mode
        if (KeySvrSessionPool->opMode() >= PCI_OP_NO_PULL_NO_PUSH) {
            *dst_len = extendOutBuffer(src_len);
            *dst = OutBuffer;
            decrypt(enc_col_name, src, src_len, OutBuffer, dst_len, sql_type);
            return 0;
        }
#endif
        dgt_sint64 enc_col_id = NamePool->getID(enc_col_name);
        if (enc_col_id < 0) {
            ErrCode = (dgt_sint32)enc_col_id;
            dgt_schar err_msg[129];
            sprintf(err_msg, "getID[%s] failed",
                    enc_col_name ? enc_col_name : "");
            PcaKeySvrSessionPool::logging(ErrCode, err_msg);
        } else {
            PcaPrivilege* priv = getPrivilege(enc_col_id);
            if (priv) {
                *dst_len = 4000;
                if (OutBufferLength == 0) {
                    delete OutBuffer;
                    OutBuffer = new dgt_uint8[OutBufferLength = 4000];
                }
                if (src_len > 2000) {
                    *dst_len =
                        4 * (dgt_sint32)ceil((double)(src_len + 64) / 3) + 32;
                    if (*dst_len > OutBufferLength) {
                        delete OutBuffer;
                        OutBuffer = new dgt_uint8[OutBufferLength = *dst_len];
                        if (PcaKeySvrSessionPool::traceLevel() > 0)
                            PcaKeySvrSessionPool::logging(
                                "SID[%d]:: OutBuffer[%d] replaced", SID,
                                OutBufferLength);
                    }
                }
                *dst = OutBuffer;
                decrypt(enc_col_id, src, src_len, OutBuffer, dst_len, sql_type,
                        priv, set_key, set_iv, (dgt_schar*)"off", pad_type);
            }
        }
        return ErrCode == 0 ? NewSqlFlag : ErrCode;
    };

    inline dgt_sint32 decrypt(const dgt_schar* enc_col_name, dgt_uint8* src,
                              dgt_sint32 src_len, dgt_uint8* dst,
                              dgt_uint32* dst_len, dgt_schar* header_flag) {
        ErrCode = 0;
#if 1  // added by chchung 2013.9.13 for adding test mode
        if (KeySvrSessionPool->opMode() >= PCI_OP_NO_PULL_NO_PUSH) {
            if (*dst_len > (dgt_uint32)src_len) *dst_len = src_len;
            memcpy(dst, src, *dst_len);
            return 0;
        }
#endif
        dgt_sint64 enc_col_id = NamePool->getID(enc_col_name);
        if (enc_col_id < 0) {
            ErrCode = (dgt_sint32)enc_col_id;
            dgt_schar err_msg[129];
            sprintf(err_msg, "getID[%s] failed",
                    enc_col_name ? enc_col_name : "");
            PcaKeySvrSessionPool::logging(ErrCode, err_msg);
        } else {
            decrypt(enc_col_id, src, src_len, dst, dst_len, 0, 0, 0, 0,
                    header_flag);
        }
        return ErrCode == 0 ? NewSqlFlag : ErrCode;
        return 0;
    }

    dgt_sint32 decrypt_vkey(dgt_sint64 virtual_key_id, dgt_uint8* src,
                            dgt_sint32 src_len, dgt_uint8* dst,
                            dgt_uint32* dst_len, dgt_uint8 target_type,
                            dgt_schar* name1 = 0, dgt_schar* name2 = 0,
                            dgt_schar* name3 = 0, dgt_schar* name4 = 0,
                            dgt_schar* name5 = 0, dgt_schar* name6 = 0,
                            dgt_schar* name7 = 0, dgt_schar* name8 = 0,
                            dgt_schar* name9 = 0, dgt_schar* name10 = 0);

    dgt_sint32 decrypt_vkey(dgt_sint64 virtual_key_id, dgt_uint8* src,
                            dgt_sint32 src_len, dgt_uint8** dst,
                            dgt_uint32* dst_len, dgt_uint8 target_type,
                            dgt_schar* name1 = 0, dgt_schar* name2 = 0,
                            dgt_schar* name3 = 0, dgt_schar* name4 = 0,
                            dgt_schar* name5 = 0, dgt_schar* name6 = 0,
                            dgt_schar* name7 = 0, dgt_schar* name8 = 0,
                            dgt_schar* name9 = 0, dgt_schar* name10 = 0);

    inline dgt_sint32 OPHUEK(dgt_sint64 enc_col_id, dgt_uint8* src,
                             dgt_sint32 src_len, dgt_uint8* dst,
                             dgt_uint32* dst_len, dgt_sint32 src_enc_flag = 1,
                             PcaPrivilege* priv = 0) {
        ErrCode = 0;
#if 1  // added by chchung 2013.9.13 for adding test mode
        if (KeySvrSessionPool->opMode() >= PCI_OP_NO_PULL_NO_PUSH) {
            if (*dst_len > (dgt_uint32)src_len) *dst_len = src_len;
            memcpy(dst, src, *dst_len);
            return 0;
        }
#endif
        if (priv == 0) priv = getPrivilege(enc_col_id);
        if (priv) {
#if 0
                        if (src_enc_flag == 0 && (dgt_uint32)src_len > priv->maxColLength()) {
                                PcaKeySvrSessionPool::logging("OPHUEK[%s]Data[%d] MaxColumnLength[%d] exceed",src,src_len,priv->maxColLength());
                                ErrCode = PS_ERR_MAX_COLUMN_LENGTH_EXCEED;
                                return ErrCode == 0 ? NewSqlFlag : ErrCode;
                        }
#endif
#if 1  // added by chchung 2013.9.13 for adding test mode
            if (KeySvrSessionPool->opMode() || priv->opMode()) {
                if (KeySvrSessionPool->opMode() == PCI_OP_NO_CRYPT_EQUAL_LOAD ||
                    (KeySvrSessionPool->opMode() == 0 && priv->opMode())) {
                    // the same load
                    dgt_uint32 tmp_dst_len = src_len + 1;
                    priv->OPHUEK(src, src_len, dst, &tmp_dst_len, src_enc_flag);
                }
                if (*dst_len > (dgt_uint32)src_len) *dst_len = src_len;
                memcpy(dst, src, *dst_len);
                return 0;
            } else {
                *dst_len = src_len + 1;
                ErrCode =
                    priv->OPHUEK(src, src_len, dst, dst_len, src_enc_flag);
            }
#else
#if 0
			*dst_len = priv->ophLength();
#else
            //			*dst_len = priv->maxColLength()+1;
            *dst_len = src_len + 1;
#endif
            ErrCode = priv->OPHUEK(src, src_len, dst, dst_len, src_enc_flag);
#endif
        }
        return ErrCode;
    };

    inline dgt_sint32 OPHUEK(dgt_sint64 enc_col_id, dgt_uint8* src,
                             dgt_sint32 src_len, dgt_uint8** dst,
                             dgt_uint32* dst_len, dgt_sint32 src_enc_flag = 1) {
        ErrCode = 0;
#if 1  // added by chchung 2013.9.13 for adding test mode
        if (KeySvrSessionPool->opMode() >= PCI_OP_NO_PULL_NO_PUSH) {
            *dst_len = extendOutBuffer(src_len);
            *dst = OutBuffer;
            OPHUEK(enc_col_id, src, src_len, OutBuffer, dst_len, src_enc_flag);
            return 0;
        }
#endif
        PcaPrivilege* priv = getPrivilege(enc_col_id);
        if (priv) {
            *dst_len = 4000;
            if (OutBufferLength == 0) {
                delete OutBuffer;
                OutBuffer = new dgt_uint8[OutBufferLength = 4000];
            }
            //*dst_len = priv->ophLength();
            // if ((*dst_len+3)*2 > OutBufferLength) {
            if (src_len > 2000) {
                if ((*dst_len + 3) * 2 > OutBufferLength) {
                    delete OutBuffer;
                    OutBuffer =
                        new dgt_uint8[OutBufferLength = (*dst_len + 3) * 2];
                    if (PcaKeySvrSessionPool::traceLevel() > 0)
                        PcaKeySvrSessionPool::logging(
                            "SID[%d]:: OutBuffer[%d] replaced", SID,
                            OutBufferLength);
                }
            }
            *dst = OutBuffer;
            OPHUEK(enc_col_id, src, src_len, OutBuffer, dst_len, src_enc_flag,
                   priv);
        }
        return ErrCode;
    };

    inline dgt_sint32 OPHUEK(const dgt_schar* enc_col_name, dgt_uint8* src,
                             dgt_sint32 src_len, dgt_uint8* dst,
                             dgt_uint32* dst_len, dgt_sint32 src_enc_flag = 1) {
        ErrCode = 0;
#if 1  // added by chchung 2013.9.13 for adding test mode
        if (KeySvrSessionPool->opMode() >= PCI_OP_NO_PULL_NO_PUSH) {
            if (*dst_len > (dgt_uint32)src_len) *dst_len = src_len;
            memcpy(dst, src, *dst_len);
            return 0;
        }
#endif
        dgt_sint64 enc_col_id = NamePool->getID(enc_col_name);
        if (enc_col_id < 0) {
            ErrCode = (dgt_sint32)enc_col_id;
            dgt_schar err_msg[129];
            sprintf(err_msg, "getID[%s] failed",
                    enc_col_name ? enc_col_name : "");
            PcaKeySvrSessionPool::logging(ErrCode, err_msg);
        } else {
            OPHUEK(enc_col_id, src, src_len, dst, dst_len, src_enc_flag);
        }
        return ErrCode;
    };

    inline dgt_sint32 OPHUEK(const dgt_schar* enc_col_name, dgt_uint8* src,
                             dgt_sint32 src_len, dgt_uint8** dst,
                             dgt_uint32* dst_len, dgt_sint32 src_enc_flag = 1) {
        ErrCode = 0;
#if 1  // added by chchung 2013.9.13 for adding test mode
        if (KeySvrSessionPool->opMode() >= PCI_OP_NO_PULL_NO_PUSH) {
            *dst_len = extendOutBuffer(src_len);
            *dst = OutBuffer;
            OPHUEK(enc_col_name, src, src_len, OutBuffer, dst_len,
                   src_enc_flag);
            return 0;
        }
#endif
        dgt_sint64 enc_col_id = NamePool->getID(enc_col_name);
        if (enc_col_id < 0) {
            ErrCode = (dgt_sint32)enc_col_id;
            dgt_schar err_msg[129];
            sprintf(err_msg, "getID[%s] failed",
                    enc_col_name ? enc_col_name : "");
            PcaKeySvrSessionPool::logging(ErrCode, err_msg);
        } else {
            PcaPrivilege* priv = getPrivilege(enc_col_id);
            if (priv) {
                *dst_len = 4000;
                if (OutBufferLength == 0) {
                    delete OutBuffer;
                    OutBuffer = new dgt_uint8[OutBufferLength = 4000];
                }
                //*dst_len = priv->ophLength();
                if (src_len > 2000) {
                    if ((*dst_len + 3) * 2 > OutBufferLength) {
                        delete OutBuffer;
                        OutBuffer =
                            new dgt_uint8[OutBufferLength = (*dst_len + 3) * 2];
                        if (PcaKeySvrSessionPool::traceLevel() > 0)
                            PcaKeySvrSessionPool::logging(
                                "SID[%d]:: OutBuffer[%d] replaced", SID,
                                OutBufferLength);
                    }
                }
                *dst = OutBuffer;
                OPHUEK(enc_col_id, src, src_len, OutBuffer, dst_len,
                       src_enc_flag, priv);
            }
        }
        return ErrCode;
    };

    inline dgt_sint32 encryptCpn(dgt_sint64 enc_col_id, dgt_uint8* src,
                                 dgt_sint32 src_len, dgt_uint8* coupon,
                                 dgt_uint32* coupon_len,
                                 PcaPrivilege* priv = 0) {
        ErrCode = 0;
#if 1  // added by chchung 2013.9.13 for adding test mode
        if (KeySvrSessionPool->opMode() >= PCI_OP_NO_PULL_NO_PUSH) {
            if (*coupon_len > (dgt_uint32)src_len) *coupon_len = src_len;
            memcpy(coupon, src, *coupon_len);
            return 0;
        }
#endif
        setNewSqlFlag();
        if (priv == 0) priv = getPrivilege(enc_col_id);
        if (priv) {
            //
            // if AuditFlag > 0 the setting the NewSqlInterval = 200000
            //
            if (KeySvrSessionPool->newSqlInterval() == 0 &&
                KeySvrSessionPool->apiMode() == 0 &&
                (priv->encAuditFlag() || priv->decAuditFlag())) {
                KeySvrSessionPool->setNewSqlInterval(200000);
            }
            PcaKeySvrSession* svr_session = 0;
            if (priv->getCryptPriv(PCI_CRYPT_OP_ENCRYPT) <= PCI_ENCRYPT_PRIV) {
                dgt_uint8 enc_fix_buf[MAX_COUPON_SRC_LEN];
                dgt_uint8* enc_data = enc_fix_buf;
                dgt_uint32 enc_len =
                    4 * (dgt_uint32)ceil((double)(src_len + 64) / 3) + 32;
                if (enc_len > MAX_COUPON_SRC_LEN)
                    enc_data = new dgt_uint8[enc_len];
                else
                    enc_len = MAX_COUPON_SRC_LEN;
                memset(enc_data, 0, enc_len);
                //
                // charater set conversion
                //
#ifdef WIN32
                dgt_sint32 rtn = 0;
#else
                dgt_sint32 rtn = convCharSet((dgt_schar*)src, src_len, priv);
#endif
#if 1  // added by chchung 2013.9.13 for adding test mode
                if (KeySvrSessionPool->opMode() || priv->opMode()) {
                    if (KeySvrSessionPool->opMode() ==
                            PCI_OP_NO_CRYPT_EQUAL_LOAD ||
                        (KeySvrSessionPool->opMode() == 0 && priv->opMode())) {
                        // the same load
                        dgt_uint32 tmp_coupon_len = *coupon_len;
                        if ((ErrCode = priv->encrypt(
                                 src, src_len, enc_data, &enc_len,
                                 KeySvrSessionPool->doubleEncCheck(), 1)) ==
                            0) {
                            if (svr_session || KeySvrSessionPool->getSession(
                                                   &svr_session) == 0) {
                                if ((ErrCode = svr_session->encryptCpn(
                                         enc_col_id, enc_data, enc_len, coupon,
                                         &tmp_coupon_len))) {
                                    PcaKeySvrSessionPool::logging(
                                        ErrCode, svr_session->errMsg());
                                }
                                if (svr_session)
                                    KeySvrSessionPool->returnSession(
                                        svr_session);
                            }
                        }
                    }
                    if (*coupon_len > (dgt_uint32)src_len)
                        *coupon_len = src_len;
                    memcpy(coupon, src, *coupon_len);
                    if (enc_data != enc_fix_buf) delete enc_data;
                    return ErrCode = 0;
                } else {
                    if (rtn >= 0) {     // in case of no conversion error
                        if (rtn > 0) {  // converted and the result size is rtn
                            src = ConvBuffer;
                            src_len = rtn;
                        }
                        if ((ErrCode = priv->encrypt(
                                 src, src_len, enc_data, &enc_len,
                                 KeySvrSessionPool->doubleEncCheck())) == 0) {
                            if (svr_session || KeySvrSessionPool->getSession(
                                                   &svr_session) == 0) {
                                if ((ErrCode = svr_session->encryptCpn(
                                         enc_col_id, enc_data, enc_len, coupon,
                                         coupon_len))) {
                                    PcaKeySvrSessionPool::logging(
                                        ErrCode, svr_session->errMsg());
                                }
                                if (svr_session)
                                    KeySvrSessionPool->returnSession(
                                        svr_session);
                            }
                        }
                    }
                }
#else
                if (rtn >= 0) {
                    if (rtn > 0) {  // converted and the result size is rtn
                        src = ConvBuffer;
                        src_len = rtn;
                    }
                    if (KeySvrSessionPool->isEncryptLocal()) {
                        ErrCode = priv->encrypt(
                            src, src_len, (dgt_uint8*)enc_data, &enc_len,
                            KeySvrSessionPool->doubleEncCheck());
                    } else {
                        if (svr_session ||
                            KeySvrSessionPool->getSession(&svr_session) == 0) {
                            if ((ErrCode = svr_session->encrypt(
                                     enc_col_id, src, src_len,
                                     (dgt_uint8*)enc_data, &enc_len))) {
                                PcaKeySvrSessionPool::logging(
                                    ErrCode, svr_session->errMsg());
                            }
                            if (svr_session)
                                KeySvrSessionPool->returnSession(svr_session);
                        }
                    }
                }
                if (svr_session ||
                    KeySvrSessionPool->getSession(&svr_session) == 0) {
                    if ((ErrCode = svr_session->encryptCpn(
                             enc_col_id, (dgt_uint8*)enc_data, enc_len, coupon,
                             coupon_len))) {
                        PcaKeySvrSessionPool::logging(ErrCode,
                                                      svr_session->errMsg());
                    }
                    if (svr_session)
                        KeySvrSessionPool->returnSession(svr_session);
                }
#endif
                if (enc_data != enc_fix_buf) delete enc_data;

            } else {
                ErrCode = PcaPrivilege::PK_NO_ENCRYPT_PRIV;
                if (priv->encCount() == 1) {
                    priv->setEncLogPriv(PCI_ENCRYPT_PRIV_ERR);
                    if (priv->isEncryptAlert()) {
                        if (svr_session ||
                            KeySvrSessionPool->getSession(&svr_session) == 0) {
                            setAlertRequest(enc_col_id, 0, 0,
                                            PS_NO_PRIV_ENCRYPT_ALERT);
                            if ((ErrCode = svr_session->alert(&AlertRequest))) {
                                PcaKeySvrSessionPool::logging(
                                    ErrCode, svr_session->errMsg());
                            }
                            if (svr_session)
                                KeySvrSessionPool->returnSession(svr_session);
                        }
                    }
                }
            }
        }
#if 0
		if (KeySvrSessionPool->newSqlInterval()) {
			gettimeofday(&LastCallTime,0);
		}
#endif
        return ErrCode == 0 ? NewSqlFlag : ErrCode;
    };

    inline dgt_sint32 encryptCpn(dgt_sint64 enc_col_id, dgt_uint8* src,
                                 dgt_sint32 src_len, dgt_uint8** coupon,
                                 dgt_uint32* coupon_len) {
        ErrCode = 0;
#if 1  // added by chchung 2013.9.13 for adding test mode
        if (KeySvrSessionPool->opMode() >= PCI_OP_NO_PULL_NO_PUSH) {
            *coupon_len = extendOutBuffer(src_len);
            *coupon = OutBuffer;
            encryptCpn(enc_col_id, src, src_len, OutBuffer, coupon_len);
            return 0;
        }
#endif
        PcaPrivilege* priv =
            getPrivilege(enc_col_id);  // get a for "enc_col_id"
        if (priv) {
            *coupon_len = 4000;
            if (OutBufferLength == 0) {
                delete OutBuffer;
                OutBuffer = new dgt_uint8[OutBufferLength = 4000];
            }
            if ((dgt_uint32)src_len > OutBufferLength) {
                delete OutBuffer;
                OutBuffer = new dgt_uint8[OutBufferLength = *coupon_len];
                if (PcaKeySvrSessionPool::traceLevel() > 0)
                    PcaKeySvrSessionPool::logging(
                        "SID[%d]:: OutBuffer[%d] replaced", SID,
                        OutBufferLength);
            }
            *coupon = OutBuffer;
            encryptCpn(enc_col_id, src, src_len, OutBuffer, coupon_len, priv);
        }
        return ErrCode == 0 ? NewSqlFlag : ErrCode;
    };

    inline dgt_sint32 encryptCpn(const dgt_schar* enc_col_name, dgt_uint8* src,
                                 dgt_sint32 src_len, dgt_uint8* coupon,
                                 dgt_uint32* coupon_len) {
        ErrCode = 0;
#if 1  // added by chchung 2013.9.13 for adding test mode
        if (KeySvrSessionPool->opMode() >= PCI_OP_NO_PULL_NO_PUSH) {
            if (*coupon_len > (dgt_uint32)src_len) *coupon_len = src_len;
            memcpy(coupon, src, *coupon_len);
            return 0;
        }
#endif
        dgt_sint64 enc_col_id = NamePool->getID(enc_col_name);
        if (enc_col_id < 0) {
            ErrCode = (dgt_sint32)enc_col_id;
            dgt_schar err_msg[129];
            sprintf(err_msg, "getID[%s] failed",
                    enc_col_name ? enc_col_name : "");
            PcaKeySvrSessionPool::logging(ErrCode, err_msg);
        } else {
            encryptCpn(enc_col_id, src, src_len, coupon, coupon_len);
        }
        return ErrCode == 0 ? NewSqlFlag : ErrCode;
    };

    inline dgt_sint32 encryptCpn(const dgt_schar* enc_col_name, dgt_uint8* src,
                                 dgt_sint32 src_len, dgt_uint8** coupon,
                                 dgt_uint32* coupon_len) {
        ErrCode = 0;
#if 1  // added by chchung 2013.9.13 for adding test mode
        if (KeySvrSessionPool->opMode() >= PCI_OP_NO_PULL_NO_PUSH) {
            *coupon_len = extendOutBuffer(src_len);
            *coupon = OutBuffer;
            encryptCpn(enc_col_name, src, src_len, OutBuffer, coupon_len);
            return 0;
        }
#endif
        dgt_sint64 enc_col_id = NamePool->getID(enc_col_name);
        if (enc_col_id < 0) {
            ErrCode = (dgt_sint32)enc_col_id;
            dgt_schar err_msg[129];
            sprintf(err_msg, "getID[%s] failed",
                    enc_col_name ? enc_col_name : "");
            PcaKeySvrSessionPool::logging(ErrCode, err_msg);
        } else {
            PcaPrivilege* priv =
                getPrivilege(enc_col_id);  // get a for "enc_col_id"
            if (priv) {
                *coupon_len = 4000;
                if (OutBufferLength == 0) {
                    delete OutBuffer;
                    OutBuffer = new dgt_uint8[OutBufferLength = 4000];
                }
                if ((dgt_uint32)src_len > OutBufferLength) {
                    delete OutBuffer;
                    OutBuffer = new dgt_uint8[OutBufferLength = *coupon_len];
                    if (PcaKeySvrSessionPool::traceLevel() > 0)
                        PcaKeySvrSessionPool::logging(
                            "SID[%d]:: OutBuffer[%d] replaced", SID,
                            OutBufferLength);
                }
                *coupon = OutBuffer;
                encryptCpn(enc_col_id, src, src_len, OutBuffer, coupon_len,
                           priv);
            }
        }
        return ErrCode == 0 ? NewSqlFlag : ErrCode;
    };

    inline dgt_sint32 decryptCpn(dgt_sint64 enc_col_id, dgt_uint8* coupon,
                                 dgt_sint32 coupon_len, dgt_uint8* dst,
                                 dgt_uint32* dst_len, PcaPrivilege* priv = 0) {
        ErrCode = 0;
#if 1  // added by chchung 2013.9.13 for adding test mode
        if (KeySvrSessionPool->opMode() >= PCI_OP_NO_PULL_NO_PUSH) {
            if (*dst_len > (dgt_uint32)coupon_len) *dst_len = coupon_len;
            memcpy(dst, coupon, *dst_len);
            return 0;
        }
#endif
        setNewSqlFlag();
        if (priv == 0) priv = getPrivilege(enc_col_id);
        if (priv) {
            //
            // if AuditFlag > 0 the setting the NewSqlInterval = 200000
            //
            if (KeySvrSessionPool->newSqlInterval() == 0 &&
                KeySvrSessionPool->apiMode() == 0 &&
                (priv->encAuditFlag() || priv->decAuditFlag())) {
                KeySvrSessionPool->setNewSqlInterval(200000);
            }
            PcaKeySvrSession* svr_session = 0;
            dgt_uint8 dec_priv;
            if ((dec_priv = priv->getCryptPriv(PCI_CRYPT_OP_DECRYPT)) <=
                PCI_DEC_PRIV_DEC) {
                if (priv->isMasking()) {
                    priv->setDecLogPriv(PCI_DEC_PRIV_MASK);
                }
            } else {
                priv->setDecLogPriv(dec_priv);
            }

            dgt_uint8 enc_data[1500];
            memset(enc_data, 0, 1500);
            dgt_uint32 enc_len = 1500;

            if (priv->decLogPrivFlag() <= PCI_DEC_PRIV_DEC ||
                priv->decLogPrivFlag() == PCI_DEC_PRIV_MASK) {
                dgt_uint32 dst_buf_len = *dst_len;
#if 1  // added by chchung 2013.9.13 for adding test mode
                if (KeySvrSessionPool->opMode() || priv->opMode()) {
                    if (KeySvrSessionPool->opMode() ==
                            PCI_OP_NO_CRYPT_EQUAL_LOAD ||
                        (KeySvrSessionPool->opMode() == 0 && priv->opMode())) {
                        // the same load
                        if ((ErrCode = priv->encrypt(
                                 coupon, coupon_len, enc_data, &enc_len,
                                 KeySvrSessionPool->doubleEncCheck(), 1)) ==
                            0) {
                            if (svr_session || KeySvrSessionPool->getSession(
                                                   &svr_session) == 0) {
                                if ((ErrCode = svr_session->encryptCpn(
                                         enc_col_id, enc_data, enc_len, dst,
                                         &dst_buf_len))) {
                                    PcaKeySvrSessionPool::logging(
                                        ErrCode, svr_session->errMsg());
                                }
                                if (svr_session)
                                    KeySvrSessionPool->returnSession(
                                        svr_session);
                            }
                        }
                    }
                    if (*dst_len > (dgt_uint32)coupon_len)
                        *dst_len = coupon_len;
                    memcpy(dst, coupon, *dst_len);
                    return ErrCode = 0;
                } else {
                    if (svr_session ||
                        KeySvrSessionPool->getSession(&svr_session) == 0) {
                        if ((ErrCode = svr_session->decryptCpn(
                                 enc_col_id, coupon, coupon_len, enc_data,
                                 &enc_len))) {
                            PcaKeySvrSessionPool::logging(
                                ErrCode, svr_session->errMsg());
                        }
                        if (svr_session)
                            KeySvrSessionPool->returnSession(svr_session);
                    }
                    ErrCode = priv->decrypt(
                        (dgt_uint8*)enc_data, enc_len, dst, dst_len, 0, 0,
                        KeySvrSessionPool->decryptFailSrcRtn());
                }
#else
                if (svr_session ||
                    KeySvrSessionPool->getSession(&svr_session) == 0) {
                    if ((ErrCode = svr_session->decryptCpn(
                             enc_col_id, coupon, coupon_len,
                             (dgt_uint8*)enc_data, &enc_len))) {
                        PcaKeySvrSessionPool::logging(ErrCode,
                                                      svr_session->errMsg());
                    }
                    if (svr_session)
                        KeySvrSessionPool->returnSession(svr_session);
                }
                if (KeySvrSessionPool->isDecryptLocal()) {
                    ErrCode = priv->decrypt(
                        (dgt_uint8*)enc_data, enc_len, dst, dst_len, 0, 0,
                        KeySvrSessionPool->decryptFailSrcRtn());
                } else {
                    if (svr_session ||
                        KeySvrSessionPool->getSession(&svr_session) == 0) {
                        if ((ErrCode = svr_session->decrypt(
                                 enc_col_id, (dgt_uint8*)enc_data, enc_len, dst,
                                 dst_len))) {
                            PcaKeySvrSessionPool::logging(
                                ErrCode, svr_session->errMsg());
                        }
                        if (svr_session)
                            KeySvrSessionPool->returnSession(svr_session);
                    }
                }
#endif
                if (ErrCode == 0) {
                    //
                    // charater set conversion for decrypted data
                    //
#ifdef WIN32
                    dgt_sint32 rtn = 0;
#else
                    dgt_sint32 rtn = convCharSet((dgt_schar*)dst,
                                                 (dgt_sint32)*dst_len, priv, 1);
#endif
                    if (rtn > 0) {
                        //
                        // converted and the result size is rtn
                        //
                        if (rtn > (dgt_sint32)dst_buf_len) {
                            ErrCode = PCI_ERR_OUT_BUFFER_TOO_SHORT;
                        } else {
                            memcpy(dst, ConvBuffer, rtn);
                            *dst_len = rtn;
                        }
                    }
                }
            }
            if (priv->decCount() == 1 &&
                priv->decLogPrivFlag() > PCI_DEC_PRIV_DEC &&
                priv->isDecryptAlert()) {
                if (svr_session ||
                    KeySvrSessionPool->getSession(&svr_session) == 0) {
                    setAlertRequest(enc_col_id, 0, 2, PS_NO_PRIV_DECRYPT_ALERT);
                    if ((ErrCode = svr_session->alert(&AlertRequest))) {
                        PcaKeySvrSessionPool::logging(ErrCode,
                                                      svr_session->errMsg());
                    }
                    if (svr_session)
                        KeySvrSessionPool->returnSession(svr_session);
                    if (PcaKeySvrSessionPool::traceLevel() > 0)
                        PcaKeySvrSessionPool::logging(
                            "SID[%d]:: no priv decrypt alert => ErrCode[%d]",
                            SID, ErrCode);
                }
            }
            if (ErrCode == 0) {
                dgt_sint32 rtn = 0;
                if (priv->decLogPrivFlag() > PCI_DEC_PRIV_DEC) {
                    //
                    // no error and no privilege
                    //
                    if (priv->decLogPrivFlag() ==
                        PCI_DEC_PRIV_ERR) {  // error return
                        ErrCode = PcaPrivilege::PK_NO_DECRYPT_PRIV;
                    } else if (priv->decLogPrivFlag() ==
                               PCI_DEC_PRIV_SRC) {  // encrypted data return
                        if (*dst_len > (dgt_uint32)coupon_len)
                            *dst_len = coupon_len;
                        memcpy(dst, coupon, *dst_len);
                    } else {
                        dgt_uint32 masking_len = priv->maskingLength(*dst_len);
                        if (masking_len > 0) {
                            dgt_uint8* cp = dst + priv->encStartPos(*dst_len);
                            dgt_uint32 mask_pttn_len = strlen(priv->maskChar());
                            if (mask_pttn_len == 0) {
                                memset(cp, PS_DFLT_MASK_CHAR, masking_len);
                            } else {
                                while (masking_len > 0) {
                                    if (masking_len <= mask_pttn_len) {
                                        memcpy(cp, priv->maskChar(),
                                               masking_len);
                                        masking_len = 0;
                                    } else {
                                        memcpy(cp, priv->maskChar(),
                                               mask_pttn_len);
                                        masking_len -= mask_pttn_len;
                                        cp += mask_pttn_len;
                                    }
                                }
                            }
                        }
                    }
                } else if ((rtn = priv->isAlert())) {
                    //
                    // decryption allowed but too many decryption try so as to
                    // alert this event
                    //
                    if (rtn < 0) {
                        AlertSqlFlag = 1;
                    } else if (rtn > 0) {
                        AlertSqlFlag = 0;
                        setAlertRequest(enc_col_id, priv->alertDecCount(), 1,
                                        PS_TOO_MANY_DECRYPT_ALERT);
                        if (svr_session ||
                            KeySvrSessionPool->getSession(&svr_session) == 0) {
                            if ((ErrCode = svr_session->alert(&AlertRequest))) {
                                PcaKeySvrSessionPool::logging(
                                    ErrCode, svr_session->errMsg());
                            }
                            if (svr_session)
                                KeySvrSessionPool->returnSession(svr_session);
                            if (PcaKeySvrSessionPool::traceLevel() > 0)
                                PcaKeySvrSessionPool::logging(
                                    "SID[%d]:: too many[%u] decrypt alert => "
                                    "ErrCode[%d]",
                                    SID, priv->decCount(), ErrCode);
                        }
                    }
                }
            }
        }
#if 0
		if (KeySvrSessionPool->newSqlInterval()) {
			gettimeofday(&LastCallTime,0);
		}
#endif
        return ErrCode == 0 ? NewSqlFlag : ErrCode;
    };

    inline dgt_sint32 decryptCpn(dgt_sint64 enc_col_id, dgt_uint8* coupon,
                                 dgt_sint32 coupon_len, dgt_uint8** dst,
                                 dgt_uint32* dst_len) {
        ErrCode = 0;
#if 1  // added by chchung 2013.9.13 for adding test mode
        if (KeySvrSessionPool->opMode() >= PCI_OP_NO_PULL_NO_PUSH) {
            *dst_len = extendOutBuffer(coupon_len);
            *dst = OutBuffer;
            decryptCpn(enc_col_id, coupon, coupon_len, OutBuffer, dst_len);
            return 0;
        }
#endif
        PcaPrivilege* priv = getPrivilege(enc_col_id);
        if (priv) {
            *dst_len = 4000;
            if (OutBufferLength == 0) {
                delete OutBuffer;
                OutBuffer = new dgt_uint8[OutBufferLength = 4000];
            }
            if ((dgt_uint32)coupon_len > OutBufferLength) {
                delete OutBuffer;
                OutBuffer = new dgt_uint8[OutBufferLength = *dst_len];
                if (PcaKeySvrSessionPool::traceLevel() > 0)
                    PcaKeySvrSessionPool::logging(
                        "SID[%d]:: OutBuffer[%d] replaced", SID,
                        OutBufferLength);
            }
            *dst = OutBuffer;
            decryptCpn(enc_col_id, coupon, coupon_len, OutBuffer, dst_len,
                       priv);
        }
        return ErrCode == 0 ? NewSqlFlag : ErrCode;
    };

    inline dgt_sint32 decryptCpn(const dgt_schar* enc_col_name,
                                 dgt_uint8* coupon, dgt_sint32 coupon_len,
                                 dgt_uint8* dst, dgt_uint32* dst_len) {
        ErrCode = 0;
#if 1  // added by chchung 2013.9.13 for adding test mode
        if (KeySvrSessionPool->opMode() >= PCI_OP_NO_PULL_NO_PUSH) {
            if (*dst_len > (dgt_uint32)coupon_len) *dst_len = coupon_len;
            memcpy(dst, coupon, *dst_len);
            return 0;
        }
#endif
        dgt_sint64 enc_col_id = NamePool->getID(enc_col_name);
        if (enc_col_id < 0) {
            ErrCode = (dgt_sint32)enc_col_id;
            dgt_schar err_msg[129];
            sprintf(err_msg, "getID[%s] failed",
                    enc_col_name ? enc_col_name : "");
            PcaKeySvrSessionPool::logging(ErrCode, err_msg);
        } else {
            decryptCpn(enc_col_id, coupon, coupon_len, dst, dst_len);
        }
        return ErrCode == 0 ? NewSqlFlag : ErrCode;
    };

    inline dgt_sint32 decryptCpn(const dgt_schar* enc_col_name,
                                 dgt_uint8* coupon, dgt_sint32 coupon_len,
                                 dgt_uint8** dst, dgt_uint32* dst_len) {
        ErrCode = 0;
#if 1  // added by chchung 2013.9.13 for adding test mode
        if (KeySvrSessionPool->opMode() >= PCI_OP_NO_PULL_NO_PUSH) {
            *dst_len = extendOutBuffer(coupon_len);
            *dst = OutBuffer;
            decryptCpn(enc_col_name, coupon, coupon_len, OutBuffer, dst_len);
            return 0;
        }
#endif
        dgt_sint64 enc_col_id = NamePool->getID(enc_col_name);
        if (enc_col_id < 0) {
            ErrCode = (dgt_sint32)enc_col_id;
            dgt_schar err_msg[129];
            sprintf(err_msg, "getID[%s] failed",
                    enc_col_name ? enc_col_name : "");
            PcaKeySvrSessionPool::logging(ErrCode, err_msg);
        } else {
            PcaPrivilege* priv = getPrivilege(enc_col_id);
            if (priv) {
                *dst_len = 4000;
                if (OutBufferLength == 0) {
                    delete OutBuffer;
                    OutBuffer = new dgt_uint8[OutBufferLength = 4000];
                }
                if ((dgt_uint32)coupon_len > OutBufferLength) {
                    delete OutBuffer;
                    OutBuffer = new dgt_uint8[OutBufferLength = *dst_len];
                    if (PcaKeySvrSessionPool::traceLevel() > 0)
                        PcaKeySvrSessionPool::logging(
                            "SID[%d]:: OutBuffer[%d] replaced", SID,
                            OutBufferLength);
                }
                *dst = OutBuffer;
                decryptCpn(enc_col_id, coupon, coupon_len, OutBuffer, dst_len,
                           priv);
            }
        }
        return ErrCode == 0 ? NewSqlFlag : ErrCode;
    };

    inline dgt_void setSqlHash(dgt_schar* sql_hash, dgt_sint32 sql_type) {
        memset(&AlertRequest, 0, sizeof(AlertRequest));
        if (sql_hash) {
            strncpy(CurrRequest.sql_hash, sql_hash, 64);
            strncpy(AlertRequest.sql_hash, sql_hash, 64);
        }
        CurrRequest.sql_type = sql_type;
        AlertRequest.sql_type = sql_type;
        //
        // the FirstCallTime & LastCallTime should be reset by the current time
        // because the time period being spent on finding "sql hash" by the
        // caller should be excluded to decide new sql boundary.
        //
        gettimeofday(&FirstCallTime, 0);
        LastCallTime = FirstCallTime;
    };

    inline dgt_void setAlertRequest(dgt_sint64 enc_col_id, dgt_sint64 dec_count,
                                    dgt_uint8 dec_no_priv_flag,
                                    dgt_uint8 op_type) {
        if (op_type != PS_TOO_MANY_DECRYPT_ALERT) {
            memset(&AlertRequest, 0, sizeof(AlertRequest));
        }
        AlertRequest.start_date = dgtime(
            &AlertRequest.start_date);  // non zero start_date means the current
                                        // request is a logging target
        AlertRequest.user_sid = UserSID;
        AlertRequest.enc_col_id = enc_col_id;
        AlertRequest.dec_count = dec_count;
        AlertRequest.dec_no_priv_flag = dec_no_priv_flag;
        AlertRequest.op_type = op_type;
    }

    inline dgt_void logCurrRequest(dgt_schar* sql_hash = 0,
                                   dgt_sint32 sql_type = 0,
                                   dgt_schar* user_id = 0) {
        if (KeySvrSessionPool->apiMode()) {
            memset(&CurrRequest, 0, sizeof(CurrRequest));
            setRequest();
            if (sql_hash) {
                strncpy(CurrRequest.sql_hash, sql_hash, 64);
            } else {
                strncpy(CurrRequest.sql_hash,
                        KeySvrSessionPool->sharedSessionProgram(), 64);
            }
            if (user_id) {
                strncpy(CurrRequest.reserved, user_id, 32);
            } else {
                strncpy(CurrRequest.reserved,
                        KeySvrSessionPool->sharedSessionUID(), 32);
            }
            if (sql_type)
                CurrRequest.sql_type = sql_type;
            else
                CurrRequest.stmt_id =
                    128;  // for api mode(nong hyup) , all sql logging

            if (KeySvrSessionPool->oltpLogMode() > 0) {
                while (PrivilegePool.setLogRequest(&CurrRequest)) {
                    KeySvrSessionPool->oltpLogging(&CurrRequest);
                }
            } else {
                PcaKeySvrSession* svr_session = 0;
                if (!KeySvrSessionPool->getSession(&svr_session)) {
                    while (PrivilegePool.setLogRequest(&CurrRequest)) {
                        if ((ErrCode = svr_session->logRequest(&CurrRequest))) {
                            PcaKeySvrSessionPool::logging(
                                ErrCode, svr_session->errMsg());
                            break;
                        }
                        if (PcaKeySvrSessionPool::traceLevel() > 0)
                            PcaKeySvrSessionPool::logging(
                                "SID[%d]:: logRequest => UserSID[%lld] "
                                "EncColID[%lld]",
                                SID, CurrRequest.user_sid,
                                CurrRequest.enc_col_id);
                    }
                }
                KeySvrSessionPool->returnSession(svr_session);
            }
        } else if (CurrRequest.start_date) {
#if 1  // added by shson 2018.04.17 for regEncrypt logging nhbank
            if (sql_hash && !strncmp(sql_hash, "reg", 3)) {
                strncpy(CurrRequest.sql_hash, sql_hash, 64);
                CurrRequest.enc_col_id = -1;  // indicator for sql_hash is set
            }
#endif

            //
            // send the current request
            //
            if (LastCallTime.tv_sec == FirstCallTime.tv_sec) {
                CurrRequest.lapse_time =
                    LastCallTime.tv_usec - FirstCallTime.tv_usec;
            } else {
                CurrRequest.lapse_time =
                    (dgt_sint64)(LastCallTime.tv_sec - FirstCallTime.tv_sec) *
                        1000000 +
                    LastCallTime.tv_usec - FirstCallTime.tv_usec;
            }
            if (KeySvrSessionPool->oltpLogMode() > 0) {
                while (PrivilegePool.setLogRequest(&CurrRequest)) {
                    KeySvrSessionPool->oltpLogging(&CurrRequest);
                }
            } else {
                PcaKeySvrSession* svr_session = 0;
                if (!KeySvrSessionPool->getSession(&svr_session)) {
                    while (PrivilegePool.setLogRequest(&CurrRequest)) {
                        if ((ErrCode = svr_session->logRequest(&CurrRequest))) {
                            PcaKeySvrSessionPool::logging(
                                ErrCode, svr_session->errMsg());
                            break;
                        }
                        if (PcaKeySvrSessionPool::traceLevel() > 0)
                            PcaKeySvrSessionPool::logging(
                                "SID[%d]:: logRequest => UserSID[%lld] "
                                "EncColID[%lld]",
                                SID, CurrRequest.user_sid,
                                CurrRequest.enc_col_id);
                    }
                    KeySvrSessionPool->returnSession(svr_session);
                }
            }
        }
        //
        // set the current request
        //
        memset(&CurrRequest, 0, sizeof(CurrRequest));
        if (sql_hash) {
            strncpy(CurrRequest.sql_hash, sql_hash, 64);
            CurrRequest.enc_col_id = -1;  // indicator for sql_hash is set
        }
        if (user_id) {
            strncpy(CurrRequest.reserved, user_id, 32);
            CurrRequest.enc_col_id = -1;  // indicator for sql_hash is set
        }
        if (sql_type) CurrRequest.sql_type = sql_type;
    };

    inline void setErrCode(dgt_sint32 err_code) { ErrCode = err_code; };
    inline dgt_sint32 getErrCode() { return ErrCode; };
    inline dgt_sint32 getNewSqlFlag() {
        if (AlertSqlFlag) return AlertSqlFlag;
        return NewSqlFlag;
    };

    //
    // for initial encryption
    //
    inline dgt_sint32 encrypt_c(dgt_sint64 enc_col_id, dgt_uint8* src,
                                dgt_sint32 src_len, dgt_uint8* dst,
                                dgt_uint32* dst_len, PcaPrivilege* priv = 0) {
        ErrCode = 0;
        if (priv == 0) priv = getPrivilege(enc_col_id);
        if (priv) {
#if 0
                        if ((dgt_uint32)src_len > priv->maxColLength()) {
                                PcaKeySvrSessionPool::logging("Data[%d] MaxColumnLength[%d] exceed",src_len,priv->maxColLength());
                                ErrCode = PS_ERR_MAX_COLUMN_LENGTH_EXCEED;
                                return ErrCode == 0 ? NewSqlFlag : ErrCode;
                        }
#endif
            PcaKeySvrSession* svr_session = 0;
            if (priv->getCryptPriv(PCI_CRYPT_OP_ENCRYPT) <=
                PCI_ENCRYPT_PRIV) {  // encryption privilege check
                                     //
                                     // charater set conversion
                                     //
#ifdef WIN32
                dgt_sint32 rtn = 0;
#else
                dgt_sint32 rtn = convCharSet((dgt_schar*)src, src_len, priv);
#endif
                if (rtn >= 0) {
                    if (rtn > 0) {  // converted and the result size is rtn
                        src = ConvBuffer;
                        src_len = rtn;
                    }
                    if (KeySvrSessionPool->isEncryptLocal()) {
                        ErrCode = priv->encrypt(
                            src, src_len, dst, dst_len,
                            KeySvrSessionPool->doubleEncCheck(), 1);
                    } else {
                        if (svr_session ||
                            KeySvrSessionPool->getSession(&svr_session) == 0) {
                            if ((ErrCode = svr_session->encrypt(
                                     enc_col_id, src, src_len, dst, dst_len))) {
                                PcaKeySvrSessionPool::logging(
                                    ErrCode, svr_session->errMsg());
                            }
                            if (svr_session)
                                KeySvrSessionPool->returnSession(svr_session);
                        }
                    }
                }
            } else {
                ErrCode = PcaPrivilege::PK_NO_ENCRYPT_PRIV;
                if (priv->encCount() == 1) {
                    priv->setEncLogPriv(PCI_ENCRYPT_PRIV_ERR);
                    //
                    // in case of no privilege & first try, need to check
                    // alerting rule
                    //
                    if (priv->isEncryptAlert()) {
                        if (svr_session ||
                            KeySvrSessionPool->getSession(&svr_session) == 0) {
                            setAlertRequest(enc_col_id, 0, 0,
                                            PS_NO_PRIV_ENCRYPT_ALERT);
                            if (svr_session->alert(&AlertRequest)) {
                                PcaKeySvrSessionPool::logging(
                                    ErrCode, svr_session->errMsg());
                            }
                            if (svr_session)
                                KeySvrSessionPool->returnSession(svr_session);
                            if (PcaKeySvrSessionPool::traceLevel() > 0)
                                PcaKeySvrSessionPool::logging(
                                    "SID[%d]:: no priv encrypt alert => [%d]",
                                    SID, ErrCode);
                        }
                    }
                }
            }
            if (priv->encCount() == PCI_ENC_LOG_COUNT) {
                if (svr_session ||
                    KeySvrSessionPool->getSession(&svr_session) == 0) {
                    if ((ErrCode = svr_session->encCount(enc_col_id,
                                                         PCI_ENC_LOG_COUNT))) {
                        PcaKeySvrSessionPool::logging(ErrCode,
                                                      svr_session->errMsg());
                    }
                    if (svr_session)
                        KeySvrSessionPool->returnSession(svr_session);
                }
                priv->setEncCount(0);
            }
        }

        return ErrCode == 0 ? NewSqlFlag : ErrCode;
    };

    inline dgt_sint32 encrypt_c(dgt_sint64 enc_col_id, dgt_uint8* src,
                                dgt_sint32 src_len, dgt_uint8** dst,
                                dgt_uint32* dst_len) {
        ErrCode = 0;
        PcaPrivilege* priv =
            getPrivilege(enc_col_id);  // get a for "enc_col_id"
        if (priv) {
            *dst_len = 4000;
            if (OutBufferLength == 0) {
                delete OutBuffer;
                OutBuffer = new dgt_uint8[OutBufferLength = 4000];
            }
            if (src_len > 2000) {
                if (priv->ophFlag()) {
                    *dst_len =
                        4 * (dgt_sint32)ceil((double)(src_len + 64) / 3) + 32 +
                        priv->ophLength();
                } else {
                    *dst_len =
                        4 * (dgt_sint32)ceil((double)(src_len + 64) / 3) + 32;
                }
                if (*dst_len > OutBufferLength) {
                    delete OutBuffer;
                    OutBuffer = new dgt_uint8[OutBufferLength = *dst_len];
                    if (PcaKeySvrSessionPool::traceLevel() > 0)
                        PcaKeySvrSessionPool::logging(
                            "SID[%d]:: OutBuffer[%d] replaced", SID,
                            OutBufferLength);
                }
            }
            *dst = OutBuffer;
            encrypt_c(enc_col_id, src, src_len, OutBuffer, dst_len, priv);
        }
        return ErrCode == 0 ? NewSqlFlag : ErrCode;
    };

    inline dgt_sint32 getKey(const dgt_schar* enc_col_name,
                             dgt_uint8* key_buffer, dgt_sint32* key_size) {
        ErrCode = 0;
        dgt_sint64 enc_col_id = NamePool->getID(enc_col_name);
        if (enc_col_id < 0) {
            ErrCode = (dgt_sint32)enc_col_id;
            dgt_schar err_msg[129];
            sprintf(err_msg, "getID[%s] failed",
                    enc_col_name ? enc_col_name : "");
            PcaKeySvrSessionPool::logging(ErrCode, err_msg);
        } else {
            PcaPrivilege* priv = getPrivilege(enc_col_id);
            if (priv) {
                ErrCode = priv->getKey(key_buffer, key_size);
                return ErrCode;
            }
        }
        return ErrCode;
    };

    inline dgt_sint64 getKeyId(const dgt_schar* enc_col_name) {
        ErrCode = 0;
        dgt_sint64 enc_col_id = NamePool->getID(enc_col_name);
        if (enc_col_id < 0) {
            ErrCode = (dgt_sint32)enc_col_id;
            dgt_schar err_msg[129];
            sprintf(err_msg, "getID[%s] failed",
                    enc_col_name ? enc_col_name : "");
            PcaKeySvrSessionPool::logging(ErrCode, err_msg);
        } else {
            PcaPrivilege* priv = getPrivilege(enc_col_id);
            if (priv) {
                dgt_sint64 key_id = 0;
                key_id = priv->getKeyId();
                return key_id;
            }
        }
        return ErrCode;
    };

    inline dgt_sint32 putExtKey(const dgt_schar* key_name, const dgt_schar* key,
                                dgt_uint16 format_no) {
        ErrCode = 0;
        PcaKeySvrSession* svr_session = 0;
        if (svr_session || KeySvrSessionPool->getSession(&svr_session) == 0) {
            if ((ErrCode = svr_session->putExtKey(key_name, key, format_no))) {
                PcaKeySvrSessionPool::logging(ErrCode, svr_session->errMsg());
            }
            if (svr_session) KeySvrSessionPool->returnSession(svr_session);
        }
        return ErrCode;
    }

    inline dgt_sint64 getEncColID(const dgt_schar* enc_col_name) {
        dgt_sint64 enc_col_id = NamePool->getID(enc_col_name);
        if (enc_col_id < 0) {
            dgt_schar err_msg[256];
            memset(err_msg, 0, 256);
            sprintf(err_msg, "getID[%s] failed",
                    enc_col_name ? enc_col_name : "");
            PcaKeySvrSessionPool::logging(enc_col_id, err_msg);
        }
        return enc_col_id;
    }
    // added by shson 2018.6.1
    inline dgt_sint64 getZoneID(const dgt_schar* zone_name) {
        dgt_sint64 zone_id = NamePool->getZoneID(zone_name);
        if (zone_id < 0) {
            dgt_schar err_msg[256];
            memset(err_msg, 0, 256);
            sprintf(err_msg, "getZoneID[%s] failed",
                    zone_name ? zone_name : "");
            PcaKeySvrSessionPool::logging(zone_id, err_msg);
        }
        return zone_id;
    }

    inline dgt_sint64 getRegEngineID(const dgt_schar* reg_engine_name) {
        dgt_sint64 reg_engine_id = NamePool->getRegEngineID(reg_engine_name);
        if (reg_engine_id < 0) {
            dgt_schar err_msg[256];
            memset(err_msg, 0, 256);
            sprintf(err_msg, "getZoneID[%s] failed",
                    reg_engine_name ? reg_engine_name : "");
            PcaKeySvrSessionPool::logging(reg_engine_id, err_msg);
        }
        return reg_engine_id;
    }

    inline dgt_sint32 logFileRequest(pc_type_file_request_in* log_request) {
        ErrCode = 0;
        log_request->user_sid = UserSID;
        PcaKeySvrSession* svr_session = 0;
        if (KeySvrSessionPool->oltpLogMode() > 0) {
            KeySvrSessionPool->oltpFileLogging(log_request);
        } else if (svr_session ||
                   KeySvrSessionPool->getSession(&svr_session) == 0) {
            if ((ErrCode = svr_session->logFileRequest(log_request))) {
                PcaKeySvrSessionPool::logging(ErrCode, svr_session->errMsg());
            }
            if (svr_session) KeySvrSessionPool->returnSession(svr_session);
        }
        return ErrCode;
    }

    inline dgt_sint32 logUserFileRequest(
        pc_type_user_file_request_in* log_request) {
        ErrCode = 0;
        PcaKeySvrSession* svr_session = 0;
        //	if (KeySvrSessionPool->oltpLogMode() > 0) {
        //		KeySvrSessionPool->oltpFileLogging(log_request);
        //} else if (svr_session || KeySvrSessionPool->getSession(&svr_session)
        //== 0) {
        if (svr_session || KeySvrSessionPool->getSession(&svr_session) == 0) {
            if ((ErrCode = svr_session->logUserFileRequest(log_request))) {
                PcaKeySvrSessionPool::logging(ErrCode, svr_session->errMsg());
            }
            if (svr_session) KeySvrSessionPool->returnSession(svr_session);
        }
        return ErrCode;
    }

    inline dgt_sint32 getKeyInfo(const dgt_schar* enc_col_name,
                                 const dgt_schar* passwd,
                                 dgt_schar* key_info_buf, dgt_uint32* buf_len) {
        ErrCode = 0;
        dgt_sint64 enc_col_id = getEncColID(enc_col_name);
        if (enc_col_id < 0) {
            ErrCode = (dgt_sint32)enc_col_id;
            return ErrCode;
        }
        PcaPrivilege* priv = getPrivilege(enc_col_id);
        if (priv) {
            PcaPrivCompiler priv_compiler;
            priv->getKeyInfo(priv_compiler);
            if ((ErrCode = priv_compiler.exportKeyInfo(enc_col_name, enc_col_id,
                                                       passwd, key_info_buf,
                                                       buf_len)) >= 0)
                return 0;
        }
        return ErrCode;
    }
#if 1
    inline dgt_sint32 getZoneParam(dgt_sint64 zone_id, dgt_schar** param) {
        ErrCode = 0;
        // get enc_zone from zone_pool
        if (PcaKeySvrSessionPool::traceLevel() > 2)
            PcaKeySvrSessionPool::logging(
                "SID::[%d] Searching EncZonePool [%lld]", SID, zone_id);
        *param = EncZonePool.getEncZoneParam(zone_id);
        if (*param == 0) {
            PcaKeySvrSession* svr_session = 0;
            if (!(ErrCode = KeySvrSessionPool->getSession(&svr_session))) {
                dgt_schar* param_out = new dgt_schar[2049];
                memset(param_out, 0, 2049);
                dgt_sint32 retry_cnt = 0;
                if ((ErrCode = svr_session->getZoneParam(zone_id, param_out))) {
                    PcaKeySvrSessionPool::logging(ErrCode,
                                                  svr_session->errMsg());
                    if (*param == 0) ErrCode = PS_ERR_ENC_ZONE_PARAM_NOT_FOUND;
                    delete param_out;
                } else {
#ifndef WIN32
                    //
                    // for character set conversion
                    //
                    dgt_schar charset[33];
                    memset(charset, 0, 33);
                    memcpy(charset, KeySvrSessionPool->charSet(), 32);
                    if (*charset && strncasecmp(charset, "UTF-8", 32)) {
                        PtCharConv ConvCharset(KeySvrSessionPool->charSet(),
                                               "UTF-8");
                        dgt_schar outbuffer[2049];
                        memset(outbuffer, 0, 2049);
                        if (ConvCharset.convCharSet(param_out, 2049, outbuffer,
                                                    2049) < 0) {
                            if (PcaKeySvrSessionPool::traceLevel() > 0)
                                PcaKeySvrSessionPool::logging(
                                    "charsetconv failed [%lld:%s]", zone_id,
                                    param_out);
                        } else {
                            memset(param_out, 0, 2049);
                            memcpy(param_out, outbuffer, 2049);
                        }
                    }
#endif
                    if (PcaKeySvrSessionPool::traceLevel() > 0)
                        PcaKeySvrSessionPool::logging(
                            "put parameters [%lld:%s]", zone_id, param_out);
                    *param = EncZonePool.putEncZone(zone_id, param_out);
                    if (*param == 0) {
                        ErrCode = PS_ERR_ENC_ZONE_PARAM_NOT_FOUND;
                        delete param_out;
                        PcaKeySvrSessionPool::logging("putEncZone Failed [%s]",
                                                      EncZonePool.getErr());
                    }
                }
                KeySvrSessionPool->returnSession(svr_session);
            } else
                PcaKeySvrSessionPool::logging(ErrCode,
                                              "get Server Session Failed");
        }  // if(*param == 0)
        return ErrCode;
    }
#endif
    inline dgt_sint32 getZoneParam(dgt_schar* zone_name, dgt_schar** param) {
        ErrCode = 0;
        dgt_sint64 zone_id = getZoneID(zone_name);
        if (zone_id < 0) {
            ErrCode = (dgt_sint32)zone_id;
            return ErrCode;
        }
        return getZoneParam(zone_id, param);
    }

    inline dgt_sint32 getRegEngine(dgt_sint64 reg_engine_id,
                                   PccRegExprSearchEngine** param) {
        ErrCode = 0;
        if (PcaKeySvrSessionPool::traceLevel() > 0)
            PcaKeySvrSessionPool::logging(
                "SID::[%d] Searching RegEnginePool [%lld]", SID, reg_engine_id);
        *param = RegEnginePool.getRegEngine(reg_engine_id);
        if (*param == 0) {
            PcaKeySvrSession* svr_session = 0;
            if (!(ErrCode = KeySvrSessionPool->getSession(&svr_session))) {
                dgt_schar* param_out = new dgt_schar[2049];
                memset(param_out, 0, 2049);
                dgt_sint32 retry_cnt = 0;
                if ((ErrCode =
                         svr_session->getRegEngine(reg_engine_id, param_out))) {
                    PcaKeySvrSessionPool::logging(ErrCode,
                                                  svr_session->errMsg());
                    ErrCode = PS_ERR_REG_PARAM_NOT_FOUND;
                } else {
#ifndef WIN32
                    //
                    // for character set conversion
                    //
                    dgt_schar charset[33];
                    memset(charset, 0, 33);
                    memcpy(charset, KeySvrSessionPool->charSet(), 32);
                    if (*charset && strncasecmp(charset, "UTF-8", 32)) {
                        PtCharConv ConvCharset(KeySvrSessionPool->charSet(),
                                               "UTF-8");
                        dgt_schar outbuffer[2049];
                        memset(outbuffer, 0, 2049);
                        if (ConvCharset.convCharSet(param_out, 2049, outbuffer,
                                                    2049) < 0) {
                            if (PcaKeySvrSessionPool::traceLevel() > 0)
                                PcaKeySvrSessionPool::logging(
                                    "charsetconv failed [%lld:%s]",
                                    reg_engine_id, param_out);
                        } else {
                            memset(param_out, 0, 2049);
                            memcpy(param_out, outbuffer, 2049);
                        }
                    }
#endif
                    if (PcaKeySvrSessionPool::traceLevel() > 0)
                        PcaKeySvrSessionPool::logging(
                            "put parameters [%lld:%s]", reg_engine_id,
                            param_out);
                    *param =
                        RegEnginePool.putRegEngine(reg_engine_id, param_out);
                    if (*param == 0) {
                        ErrCode = PS_ERR_REG_PARAM_NOT_FOUND;
                        PcaKeySvrSessionPool::logging(
                            "putRegEngine Failed [%s]", RegEnginePool.getErr());
                    }
                }
                delete[] param_out;  // one
                KeySvrSessionPool->returnSession(svr_session);
            } else
                PcaKeySvrSessionPool::logging(ErrCode,
                                              "get Server Session Failed");
        }  // if(*param == 0) end
        return ErrCode;
    }

    inline dgt_sint32 getRegEngine(dgt_schar* reg_engine_name,
                                   PccRegExprSearchEngine** param) {
        ErrCode = 0;
        dgt_sint64 reg_engine_id = getRegEngineID(reg_engine_name);
        if (reg_engine_id < 0) {
            ErrCode = (dgt_sint32)reg_engine_id;
            return ErrCode;
        }
        return getRegEngine(reg_engine_id, param);
    }

    inline dgt_sint32 getCryptParam(dgt_schar* crypt_param_name,
                                    dgt_schar** param) {
        ErrCode = 0;
        if (PcaKeySvrSessionPool::traceLevel() > 2)
            PcaKeySvrSessionPool::logging(
                "SID[%d] Searching CryptParamPool [%s]", SID, crypt_param_name);
        *param = CryptParamPool.getCryptParam(crypt_param_name);
        if (*param == 0) {
            PcaKeySvrSession* svr_session = 0;
            if (!(ErrCode = KeySvrSessionPool->getSession(&svr_session))) {
                dgt_schar* param_out = new dgt_schar[2049];
                memset(param_out, 0, 2049);
                dgt_sint32 retry_cnt = 0;
                if ((ErrCode = svr_session->getCryptParam(crypt_param_name,
                                                          param_out))) {
                    PcaKeySvrSessionPool::logging(ErrCode,
                                                  svr_session->errMsg());
                    ErrCode = PS_ERR_CRYPT_PARAM_NOT_FOUND;
                } else {
                    if (PcaKeySvrSessionPool::traceLevel() > 2)
                        PcaKeySvrSessionPool::logging("put parameters [%s:%s]",
                                                      crypt_param_name,
                                                      param_out);
                    *param = CryptParamPool.putCryptParam(crypt_param_name,
                                                          param_out);
                    if (*param == 0) {
                        ErrCode = PS_ERR_CRYPT_PARAM_NOT_FOUND;
                        PcaKeySvrSessionPool::logging(
                            "putCryptParam Failed [%s]",
                            CryptParamPool.getErr());
                    }
                }
                KeySvrSessionPool->returnSession(svr_session);
            } else
                PcaKeySvrSessionPool::logging(ErrCode,
                                              "get Server Session Failed");
        }  // if(*param == 0) end
        return ErrCode;
    }

    // added by mwpark 2017.08.22
    inline dgt_sint32 encryptLengthWithVirtualKey(
        dgt_sint64 virtual_key_id, dgt_sint32 src_len, dgt_uint8 crypt_type,
        dgt_uint8 target_type, dgt_schar* name1 = 0, dgt_schar* name2 = 0,
        dgt_schar* name3 = 0, dgt_schar* name4 = 0, dgt_schar* name5 = 0,
        dgt_schar* name6 = 0, dgt_schar* name7 = 0, dgt_schar* name8 = 0,
        dgt_schar* name9 = 0, dgt_schar* name10 = 0) {
        PcaPrivilege* priv = getVKeyPrivilege(
            virtual_key_id, crypt_type, target_type, name1, name2, name3, name4,
            name5, name6, name7, name8, name9, name10);
        dgt_sint32 rtn = 0;
        if (priv && priv->encColID()) {
            rtn = encryptLength(priv->encColID(), src_len);
        } else {
            rtn = getErrCode();
        }
        return rtn;
    }

    inline PcaKeySvrSessionPool* keySvrSessionPool() {
        return KeySvrSessionPool;
    }

    // for file crypt stream
    inline dgt_uint32 getFileHeaderFlag() {
        return FileHeaderFlag;
    };  // read: header skip / write: header write
    inline dgt_uint32 getFileRealBytes() {
        return FileRealBytes;
    };  // read: read bytes / write : wirte bytes
    inline dgt_schar* getFileKeyName() { return FileKeyName; };
    inline dgt_schar* getFileName() { return FileName; };
    inline dgt_uint32 getFileFlags() { return FileFlags; };
    inline dgt_sint32 getFileMode() { return FileMode; };

    inline dgt_void setFileHeaderFlag() { FileHeaderFlag = 1; };
    inline dgt_void setFileRealBytes(dgt_uint32 real_bytes) {
        FileRealBytes = real_bytes;
    };
    inline dgt_void setFileOpen(const dgt_schar* key_name = 0,
                                const dgt_schar* file_name = 0,
                                dgt_uint32 flags = 0, dgt_uint32 mode = 0) {
        FileHeaderFlag = 0;
        FileRealBytes = 0;

        strncpy(FileKeyName, key_name, 299);
        strncpy(FileName, file_name, 299);
        FileFlags = flags;
        FileMode = mode;
    };

    // for file pattern detect logging
    inline dgt_sint32 logDetectFileRequest(
        pc_type_detect_file_request_in* log_request, DgcMemRows* log_data) {
        ErrCode = 0;
        PcaKeySvrSession* svr_session = 0;
        if (svr_session || KeySvrSessionPool->getSession(&svr_session) == 0) {
            if ((ErrCode = svr_session->logDetectFileRequest(log_request,
                                                             log_data))) {
                PcaKeySvrSessionPool::logging(ErrCode, svr_session->errMsg());
            }
            if (svr_session) KeySvrSessionPool->returnSession(svr_session);
        }
        return ErrCode;
    }
    inline dgt_sint32 getDetectFileRequest(DgcMemRows* get_request) {
        ErrCode = 0;
        PcaKeySvrSession* svr_session = 0;
        if (svr_session || KeySvrSessionPool->getSession(&svr_session) == 0) {
            if ((ErrCode = svr_session->getDetectFileRequest(get_request))) {
                PcaKeySvrSessionPool::logging(ErrCode, svr_session->errMsg());
            }
            if (svr_session) KeySvrSessionPool->returnSession(svr_session);
        }
        return ErrCode;
    }

    // for get rsa key
    inline dgt_sint32 getRsaKey(dgt_schar* key_name, dgt_schar** key_string) {
        ErrCode = 0;
        if (PcaKeySvrSessionPool::traceLevel() > 2)
            PcaKeySvrSessionPool::logging("SID::[%d] Searching RsaKeyPool [%s]",
                                          SID, key_name);
        *key_string = RsaKeyPool.getRsaKey(key_name);
        if (*key_string == 0) {
            PcaKeySvrSession* svr_session = 0;
            if (!(ErrCode = KeySvrSessionPool->getSession(&svr_session))) {
                dgt_schar* key_out = new dgt_schar[2049];
                memset(key_out, 0, 2049);
                dgt_sint32 retry_cnt = 0;
                if ((ErrCode = svr_session->getRsaKey(key_name, key_out))) {
                    PcaKeySvrSessionPool::logging(ErrCode,
                                                  svr_session->errMsg());
                    ErrCode = PS_ERR_RSA_KEY_NOT_FOUND;
                    delete key_out;
                } else {
                    if (PcaKeySvrSessionPool::traceLevel() > 2)
                        PcaKeySvrSessionPool::logging("put rsa_key [%s]",
                                                      key_name);
                    *key_string = RsaKeyPool.putRsaKey(key_name, key_out);
                    if (*key_string == 0) {
                        ErrCode = PS_ERR_RSA_KEY_NOT_FOUND;
                        PcaKeySvrSessionPool::logging("putRsaKey Failed [%s]",
                                                      RsaKeyPool.getErr());
                        delete key_out;
                    }
                }
                KeySvrSessionPool->returnSession(svr_session);
            } else
                PcaKeySvrSessionPool::logging(ErrCode,
                                              "get Server Session Failed");
        }
        return ErrCode;
    }
};

#endif
