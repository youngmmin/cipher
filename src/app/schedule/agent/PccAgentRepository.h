/*******************************************************************
 *   File Type          :       File Cipher Agent classes declaration and
definition
 *   Classes            :       PccAgentRepository
 *   Implementor        :       chchung
 *   Create Date        :       2017. 06. 18
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_AGENT_REPOSITORY_H
#define PCC_AGENT_REPOSITORY_H

#include "PccAgentCryptJobPool.h"
#include "PccAgentMsg.h"
#include "PccCorePool.h"
#include "PccCryptManagerPool.h"

class PccAgentRepository : public DgcObject {
   private:
    PccCorePool CorePool;
    PccCryptManagerPool ManagerPool;

   protected:
   public:
    PccAgentRepository(PccAgentCryptJobPool& job_pool);
    virtual ~PccAgentRepository();

    inline PccCorePool& corePool() { return CorePool; };
    inline PccCryptManagerPool& managerPool() { return ManagerPool; };
};

#endif
