/*******************************************************************
 *   File Type          :       test
 *   Classes            :       PfccAlertDeadProcess
 *   Implementor        :       jhpark
 *   Create Date        :       2017. 9. 28
 *   Description        :       echo external procedure
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PFCC_ALERT_DEAD_PROCESS_H
#define PFCC_ALERT_DEAD_PROCESS_H

#include "DgcExtProcedure.h"

typedef struct {
    dgt_sint64 enc_tgt_sys_id;
    dgt_sint64 dead_pid;
    dgt_schar pname[129];
} pfct_alert_dead_proc_in;

class PfccAlertDeadProcess : public DgcExtProcedure {
   private:
   protected:
   public:
    PfccAlertDeadProcess(const dgt_schar* name);
    virtual ~PfccAlertDeadProcess();
    virtual DgcExtProcedure* clone();
    virtual dgt_sint32 execute() throw(DgcExcept);
};

#endif
