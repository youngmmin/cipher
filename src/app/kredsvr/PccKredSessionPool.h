/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccKredSessionPool
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 17
 *   Description        :       kred session pool
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_KRED_SESSION_POOL_H
#define PCC_KRED_SESSION_POOL_H

#include "DgcCliConnection.h"
#include "DgcSession.h"
#include "PcTableType.h"
#include "PccTableTypes.h"
#include "PciMsgTypes.h"

typedef struct {
    dgt_schar name[33];
    dgt_schar ip[65];
    DgcCliConnection* connection;
} pksp_type_link;

class PccKredSessionPool : public DgcObject {
   private:
    static pksp_type_link Gateway1;
    static pksp_type_link Gateway2;
    static pksp_type_link Agent;

    static dgt_sint32 getConnection(pksp_type_link* link) throw(DgcExcept);

   protected:
   public:
    static dgt_void initialize(DgcSession* kred_session);
    static dgt_sint64 getUserSID(pc_type_open_sess_in* uinfo,
                                 dgt_sint32* auth_fail_code) throw(DgcExcept);
    static pt_type_sess_user* getSessUser(dgt_sint64 psu_id) throw(DgcExcept);
};

#endif
