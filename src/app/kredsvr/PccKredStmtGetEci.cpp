/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccKredStmtGetEci
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 13
 *   Description        :       KRED get key statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccKredStmtGetEci.h"

#include "DgcDbProcess.h"

PccKredStmtGetEci::PccKredStmtGetEci(DgcPhyDatabase* pdb, DgcSession* session,
                                     DgcSqlTerm* stmt_term)
    : PccKredStmt(pdb, session, stmt_term), NumRtnRows(0) {
    SelectListDef = new DgcClass("select_list", 1);
    SelectListDef->addAttr(DGC_SB8, 0, "enc_col_id");
}

PccKredStmtGetEci::~PccKredStmtGetEci() {}

dgt_sint32 PccKredStmtGetEci::execute(
    DgcMemRows* mrows, dgt_sint8 delete_flag) throw(DgcLdbExcept,
                                                    DgcPdbExcept) {
    if (!mrows || !mrows->next()) {
        THROWnR(
            DgcLdbExcept(DGC_EC_LD_STMT_ERR, new DgcError(SPOS, "no bind row")),
            -1);
    }
    defineUserVars(mrows);
    //
    // parsing name
    //
    dgt_schar ec_name[132];
    memset(ec_name, 0, 132);
    strncpy(ec_name, (dgt_schar*)mrows->data(), 131);
    dgt_schar sql_text[1024];
    if (strncmp(ec_name, PCI_DFLT_HASH_COL_NAME, 131) == 0) {
        sprintf(sql_text,
                "select a.enc_col_id from pct_enc_column a, pct_encrypt_key f"
                " where a.key_id = f.key_id"
                "   and f.cipher_type = 4");
        DgcSqlStmt* sql_stmt = DgcDbProcess::db().getStmt(
            DgcDbProcess::sess(), sql_text, strlen(sql_text));
        DgcExcept* e = 0;
        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
            e = EXCEPTnC;
            delete sql_stmt;
            RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
        }
        dgt_sint64* tmp_id;
        if ((tmp_id = (dgt_sint64*)sql_stmt->fetch()) == 0) {
            //
            // name not found
            //
            EncColID = -30351;
        } else {
            EncColID = *tmp_id;
        }
        if ((tmp_id = (dgt_sint64*)sql_stmt->fetch())) {
            //
            // ambiguous name
            //
            EncColID = -30352;
        }
        delete EXCEPTnC;
        delete sql_stmt;
    } else {
        dgt_schar* last;
        const dgt_schar* names[4] = {"", "", "", ""};
        if (*ec_name) {
            dgt_sint32 num_names = 1;
            names[0] = strtok_r(ec_name, ".", &last);
            for (dgt_sint32 i = 1;
                 i <= 3 && (names[i] = strtok_r(0, ".", &last)); i++)
                num_names++;
            if (num_names < 4)
                for (dgt_sint32 i = 0; i < 4; i++)
                    if (i < num_names)
                        names[3 - i] = names[num_names - i - 1];
                    else
                        names[3 - i] = "";
        }
        DgcMemRows v_bind(4);
        v_bind.addAttr(DGC_SCHR, 130, "col_name");
        v_bind.addAttr(DGC_SCHR, 130, "tab_name");
        v_bind.addAttr(DGC_SCHR, 33, "schema_name");
        v_bind.addAttr(DGC_SCHR, 33, "db_name");
        v_bind.reset();
        v_bind.add();
        v_bind.next();
        memcpy(v_bind.getColPtr(1), names[3], 130);
        memcpy(v_bind.getColPtr(2), names[2], 130);
        memcpy(v_bind.getColPtr(3), names[1], 33);
        memcpy(v_bind.getColPtr(4), names[0], 33);
        v_bind.rewind();
        sprintf(
            sql_text,
            "select a.enc_col_id from pct_enc_column a, pct_encrypt_key f, "
            "pct_enc_table b, pct_enc_schema c, pt_database d "
            " where upper(a.column_name) = "
            "upper(decode(:1,'',a.column_name,:1))"
            "   and a.key_id = f.key_id"
            //			"   and f.cipher_type != 4"
            "   and a.enc_tab_id = b.enc_tab_id"
            "   and upper(b.table_name) = upper(decode(:2,'',b.table_name,:2))"
            "   and b.schema_id = c.schema_id"
            "   and upper(c.schema_name) = "
            "upper(decode(:3,'',c.schema_name,:3))"
            "   and c.db_id = d.db_id"
            "   and upper(d.db_name) = upper(decode(:4,'',d.db_name,:4))");
        DgcSqlStmt* sql_stmt = DgcDbProcess::db().getStmt(
            DgcDbProcess::sess(), sql_text, strlen(sql_text));
        DgcExcept* e = 0;
        if (sql_stmt == 0 || sql_stmt->execute(&v_bind, 0) < 0) {
            e = EXCEPTnC;
            delete sql_stmt;
            RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
        }
        dgt_sint64* tmp_id;
        if ((tmp_id = (dgt_sint64*)sql_stmt->fetch()) == 0) {
            //
            // name not found
            //
            EncColID = -30351;
        } else {
            EncColID = *tmp_id;
        }
        if ((tmp_id = (dgt_sint64*)sql_stmt->fetch())) {
            //
            // ambiguous name
            //
            EncColID = -30352;
        }
        delete EXCEPTnC;
        delete sql_stmt;
    }
    IsExecuted = 1;
    NumRtnRows = 0;
    return 0;
}

dgt_uint8* PccKredStmtGetEci::fetch() throw(DgcLdbExcept, DgcPdbExcept) {
    if (IsExecuted == 0) {
        THROWnR(
            DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                         new DgcError(SPOS, "can't fetch without execution")),
            0);
    }
    if (NumRtnRows++ == 0) return (dgt_uint8*)&EncColID;
    THROWnR(DgcLdbExcept(DGC_EC_PD_NOT_FOUND, new DgcError(SPOS, "not found")),
            0);
    return 0;
}
