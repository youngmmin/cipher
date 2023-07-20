/*******************************************************************
 *   File Type          :       File Cipher Agent classes declaration and
definition
 *   Classes            :       PccAgentRepository
 *   Implementor        :       chchung
 *   Create Date        :       2017. 06. 30
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccAgentRepository.h"

PccAgentRepository::PccAgentRepository(PccAgentCryptJobPool& job_pool)
    : ManagerPool(job_pool, CorePool) {}

PccAgentRepository::~PccAgentRepository() {}
