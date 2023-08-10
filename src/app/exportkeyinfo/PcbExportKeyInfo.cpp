/*******************************************************************
 *   File Type          :       export key information command
 *   Classes            :       PccExpKeyInfo
 *   Implementor        :       chchung
 *   Create Date        :       2017. 05. 32
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "PcaApiSessionPool.h"

static const int PcAPI_ERR_INVALID_SID = -30302;

int getSession(const char* client_ip) {
    return PcaApiSessionPool::getApiSession(client_ip, "", "", "", "", "", 0);
}

int getKeyInfo(int api_sid, const char* key_name, char* key_info_buffer,
               unsigned int* buffer_length, const char* password) {
    if (api_sid < 0 && (api_sid = getSession("")) < 0) return api_sid;
    PcaApiSession* session = PcaApiSessionPool::getApiSession(api_sid);
    if (!session) return PcAPI_ERR_INVALID_SID;
    dgt_sint32 rtn =
        session->getKeyInfo(key_name, password, key_info_buffer, buffer_length);
    return rtn;
}

int main(int argc, char** argv) {
    char* passwd = 0;
    if (argc != 2 && argc != 3) {
        printf("usage: pcp_exp_key_info <enc_col_name> [password]\n");
        return 1;
    } else if (argc == 3) {
        passwd = argv[2];
    }
    int sid;
    if ((sid = getSession("")) < 0) {
        printf("getSession Failed[%d]\n", sid);
        return sid;
    }
    char key_info_buffer[2049] = {
        0,
    };
    unsigned int buf_len = 2048;
    int rtn = getKeyInfo(sid, argv[1], key_info_buffer, &buf_len, passwd);
    if (rtn < 0) {
        printf("getKeyInfo Failed[%d]\n", rtn);
        return rtn;
    }
    printf("Key[%s:%u] =>\n(key_info=\"%s\")\n", argv[1], buf_len,
           key_info_buffer);
    return 0;
}
