/*******************************************************************
 *   File Type          :       File Cipher Agent classes definition
 *   Classes            :       PccCryptManagerPool
 *   Implementor        :       chchung
 *   Create Date        :       2017. 06. 30
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccCryptManagerPool.h"

PccCryptManagerPool::PccCryptManagerPool(PccAgentCryptJobPool& job_pool,
                                         PccCorePool& core_pool)
    : JobPool(job_pool), CorePool(core_pool), NumManagers(0) {}

PccCryptManagerPool::~PccCryptManagerPool() {
    for (dgt_sint32 i = 0; i < MAX_MANAGERS; i++) {
        if (Managers[i] && Managers[i]->isAlive()) Managers[i]->stop();
    }
    for (;;) {
        dgt_sint32 alive_count = 0;
        for (dgt_sint32 i = 0; i < MAX_MANAGERS; i++) {
            if (Managers[i] && Managers[i]->isAlive()) alive_count++;
        }
        if (alive_count == 0) break;
        napAtick();
    }
    for (dgt_sint32 i = 0; i < MAX_MANAGERS; i++) {
        if (Managers[i]) delete Managers[i];
    }
}

dgt_sint32 PccCryptManagerPool::addManagers(
    dgt_sint32 num_managers, dgt_sint32 agent_mode, dgt_schar* enc_col_name,
    dgt_schar* header_flag, dgt_sint32 buffer_size) throw(DgcExcept) {
    dgt_sint32 start_count = 0;
    for (dgt_sint32 i = 0; i < num_managers; i++) {
        if (NumManagers < MAX_MANAGERS) {
            PccCryptManager* manager = 0;
            if (agent_mode > 0) {
                manager =
                    new PccCryptManager(JobPool, CorePool, i + 1, agent_mode,
                                        enc_col_name, header_flag, buffer_size);
            } else {
                manager = new PccCryptManager(JobPool, CorePool, i + 1);
            }

            if (manager->start(1)) {
                DgcExcept* e = EXCEPTnC;
                delete manager;
                RTHROWnR(e, DgcError(SPOS, "start[PccCryptManager] failed"),
                         -1);
            }
            Managers[NumManagers++] = manager;
            start_count++;
        }
    }
    return start_count;
}

dgt_sint32 PccCryptManagerPool::stopManagers(dgt_sint32 num_managers) {
    dgt_sint32 stop_count = 0;
    if (num_managers == 0) num_managers = NumManagers;
    for (dgt_sint32 i = 0; i < NumManagers && num_managers > 0; i++) {
        if (Managers[i]) {
            Managers[i]->askStop();
            if (Managers[i]->workStage() > 20) {
                num_managers--;
                stop_count++;
            }
        }
    }
    return stop_count;
}

dgt_sint32 PccCryptManagerPool::cleanManagers(dgt_sint32 force_flag) throw(
    DgcExcept) {
    dgt_sint32 clean_count = 0;
    for (dgt_sint32 i = 0; i < NumManagers; i++) {
        if (Managers[i]->isAlive() && force_flag) {
            if (Managers[i]->stop(DGC_WSTOP_FORCE) < 0) {
                ATHROWnR(DgcError(SPOS, "stop(FORCE) failed"), -1);
            }
        }
        dgt_uint32 wait_cnt = 0;
        while (Managers[i]->isAlive() && wait_cnt < 5000) {
            napAtick();
            wait_cnt++;
        }
        if (Managers[i]->isAlive() == 0) {
            clean_count++;
            delete Managers[i];
            Managers[i] = 0;
        }
    }
    NumManagers -= clean_count;
    return clean_count;
}
