/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccAgentCursorTable
 *   Implementor        :       Jaehun
 *   Create Date        :       2017. 6. 30
 *   Description        :       
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccAgentCursorTable.h"


PccAgentCursorTable::PccAgentCursorTable(dgt_uint32 max_open_cursors)
{
	MaxOpenCursors=max_open_cursors;
	OpenCursors=new PccAgentCursor[MaxOpenCursors];
}


PccAgentCursorTable::~PccAgentCursorTable()
{
	if (OpenCursors != 0) {
		closeAllCursors();
		delete[] OpenCursors;
	}
}


PccAgentStmt* PccAgentCursorTable::getStmt(dgt_uint32 cursor) throw(DgcDbNetExcept)
{
	if (cursor == 0 || cursor > MaxOpenCursors || OpenCursors[cursor-1].agentStmt() == 0) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_CUR,new DgcError(SPOS,"invalid cursor[%d]",cursor)),0);
	}
	return OpenCursors[cursor-1].agentStmt();
}


dgt_uint32 PccAgentCursorTable::openCursor(PccAgentStmt* agent_stmt,dgt_uint32 cursor) throw(DgcDbNetExcept)
{
	if (cursor == 0) {
		for(cursor=0; cursor<MaxOpenCursors; cursor++) {
			if (OpenCursors[cursor].usedFlag() == 0) {
				OpenCursors[cursor].open(agent_stmt);
				return cursor+1;
			}
		}
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_CUR,
			new DgcError(SPOS,"reach the MaxOpenCursors[%d]",MaxOpenCursors)),0);
	}
	if (cursor > MaxOpenCursors) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_CUR,new DgcError(SPOS,"invalid cursor[%d]",cursor)),0);
	}
	OpenCursors[cursor-1].open(agent_stmt);
	return cursor;
}
		

dgt_void PccAgentCursorTable::closeCursor(dgt_uint32 cursor)
{
	if (cursor > 0 && cursor <= MaxOpenCursors) OpenCursors[cursor-1].close();
}


dgt_void PccAgentCursorTable::closeStmt(dgt_uint32 cursor)
{
	if (cursor > 0 && cursor <= MaxOpenCursors) OpenCursors[cursor-1].closeStmt();
}


dgt_void PccAgentCursorTable::closeAllCursors()
{
	for(dgt_uint32 cursor=0; cursor<MaxOpenCursors; cursor++) OpenCursors[cursor].close();
}
