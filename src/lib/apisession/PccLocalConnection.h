/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccLocalConnection
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 11. 27
 *   Description        :       petra cipher local database connection
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_LOCAL_CONNECION_H
#define PCC_LOCAL_CONNECION_H

#include "DgcCliConnectionImpl.h"

class PccLocalConnection : public DgcCliConnectionImpl {
   private:
    DgcCliConnection* Connection;
    dgt_uint16 InTimeOut;
    dgt_uint16 OutTimeOut;

   protected:
   public:
    PccLocalConnection(dgt_uint16 in_timeout, dgt_uint16 out_timeout,
                       dgt_uint32 max_open_cursors = DGC_MAX_OPEN_CURSORS);
    virtual ~PccLocalConnection();

    virtual dgt_sint8 connect(
        dgt_schar* shome,           // database home
        const dgt_schar* sid = 0,   // database instance id
        const dgt_schar* uid = 0,   // database user id
        const dgt_schar* pswd = 0,  // database user password
        const dgt_schar* pname = 0  // client program name
        ) throw(DgcExcept);
    virtual DgcCliStmt* getStmt(dgt_uint8 mode = 0) throw(DgcExcept);
    virtual dgt_sint8 disconnect() throw(DgcExcept);
    virtual dgt_void dump(DgcBufferStream* bs);
};

#endif
