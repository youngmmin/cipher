/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccAgentCursorTable
 *   Implementor        :       Jaehun
 *   Create Date        :       2017. 6. 30
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_AGENT_CURSOR_TABLE_H
#define PCC_AGENT_CURSOR_TABLE_H

#include "DgcDbNet.h"
#include "PccAgentCursor.h"

class PccAgentCursorTable : public DgcObject {
   private:
    dgt_uint32 MaxOpenCursors;    // the number of current max open cursors
    PccAgentCursor* OpenCursors;  // open cursors
   protected:
   public:
    PccAgentCursorTable(dgt_uint32 max_open_cursors);
    ~PccAgentCursorTable();

    PccAgentStmt* getStmt(dgt_uint32 cursor) throw(DgcDbNetExcept);
    dgt_uint32 openCursor(PccAgentStmt* agent_stmt,
                          dgt_uint32 cursor = 0) throw(DgcDbNetExcept);
    dgt_void closeCursor(dgt_uint32 cursor);
    dgt_void closeStmt(dgt_uint32 cursor);
    dgt_void closeAllCursors();
};

#endif
