/*******************************************************************
 *   File Type          :       File Cipher Agent classes declaration and
definition
 *   Classes            :       PccJobRepository
 *   Implementor        :       chchung
 *   Create Date        :       2017. 06. 30
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccJobRepository.h"

PccJobRepository::PccJobRepository(dgt_sint32 trace_level)
    : DirPool(ZonePool, Schedule, FileQueue, MigrationFileQueue, trace_level),
      JobType(0) {
    TraceLevel = trace_level;
}

PccJobRepository::~PccJobRepository() {}
