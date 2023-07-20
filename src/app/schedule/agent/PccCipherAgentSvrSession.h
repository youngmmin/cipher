/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccCipherAgentSvrSession
 *   Implementor        :       jhpark
 *   Create Date        :       2017. 10. 24
 *   Description        :       agent statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_CIPHER_AGENT_SVR_SESSION_H
#define PCC_CIPHER_AGENT_SVR_SESSION_H

#include "DgcBgmrList.h"
#include "DgcDgMsgStream.h"
#include "DgcWorker.h"
#include "PccAgentCursorTable.h"
#include "PccAgentRepository.h"

class PccCipherAgentSvrSession : public DgcWorker {
   private:
    static const dgt_sint16 NOT_FOUND = -209;
    static const dgt_sint32 NO_SESSION_SLEEP_COUNT = 5;

    PccAgentCryptJobPool& JobPool;
    dgt_sint32 SessID;
    DgcSockClient* CommStream;   // communication stream
    DgcPacketStream* PktStream;  // packet stream
    DgcDgMsgStream* MsgStream;   // message stre
    PccAgentCursorTable CursorTable;

    DgcSession Session;
    dgt_sint32 NoSessionSleepCount;
    dgt_sint32 CurrSleepCount;
    dgt_sint32 SkipCheckConn;
    dgt_schar* PrimaryIP;
    dgt_uint16 PrimaryPort;
    dgt_schar* SecondaryIP;
    dgt_uint16 SecondaryPort;
    PccAgentStmt* CurrStmt;
    DgcMemRows* UserVarRows;

    dgt_uint8 BrokenConnFlag;
    dgt_uint8 CheckConnFlag;
    dgt_uint8 StopFlag;

    dgt_sint32 talkType() throw(DgcExcept);
    dgt_sint32 makeConnection(dgt_schar* ip, dgt_uint16 port) throw(DgcExcept);

    dgt_sint32 doRequest(DgcMsgDgiSqlRq* srm) throw(DgcExcept);
    dgt_sint32 doResponse(DgcMsgDgiSqlRq* srm) throw(DgcExcept);

    virtual dgt_void in() throw(DgcExcept);
    virtual dgt_sint32 run() throw(DgcExcept);
    virtual dgt_void out() throw(DgcExcept);

    inline dgt_void resetIBuf() { PktStream->resetIBuf(); };
    inline dgt_sint32 setPacket(dgt_uint8 type = 0) throw(DgcOsExcept,
                                                          DgcStreamExcept) {
        return PktStream->setPacket(type);
    };
    inline dgt_sint32 moveNext() { return PktStream->moveNext(); };
    inline dgt_void mvicdpl() { PktStream->mvicdpl(); };
    inline dgt_uint8 icpt() { return PktStream->icpt(); };
    inline DgcPacket* newPacket(dgt_uint8 type,
                                DgcPacket* packet = 0) throw(DgcOsExcept,
                                                             DgcStreamExcept) {
        return PktStream->newPacket(type, packet);
    };

   protected:
   public:
    PccCipherAgentSvrSession(PccAgentCryptJobPool& job_pool, dgt_sint32 sess_id,
                             dgt_sint32 no_sess_sleep_cnt, dgt_schar* p_ip,
                             dgt_uint16 p_port, dgt_schar* s_ip = 0,
                             dgt_uint16 s_port = 0);
    virtual ~PccCipherAgentSvrSession();

    inline dgt_sint32 setBrokenConnFlag() { return BrokenConnFlag = 1; };
    inline dgt_sint32 sessID() { return SessID; };
    inline dgt_sint32 brokenConnFlag() { return BrokenConnFlag; };
    inline dgt_void askStop() { StopFlag = 1; };
    dgt_sint32 connect() throw(DgcExcept);
};

#endif
