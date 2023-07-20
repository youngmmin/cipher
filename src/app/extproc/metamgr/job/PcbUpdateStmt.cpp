/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PcbUpdateStmt
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 1. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PcbUpdateStmt.h"

PcbUpdateStmt::PcbUpdateStmt(PcbCipherTable* cipher_table,
                             dgt_uint32 array_size)
    : PcbStmt(cipher_table, array_size) {}

PcbUpdateStmt::~PcbUpdateStmt() {}
