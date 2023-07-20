/*******************************************************************
 *   File Type          :       File Crypt Command
 *   Classes            :       PccFileCrypt
 *   Implementor        :       chchung
 *   Create Date        :       2017. 04. 24
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PccFileCryptor.h"

int main(int argc, char **argv) {
    if (argc < 4) {
        printf(
            "usage1 : pcp_file_crypt <url|program_id> <encrypt|decrypt> "
            "<parameter_file>\n");
        printf(
            "usage2 : pcp_file_crypt <encrypt|decrypt> <enc_col_name> "
            "<in_file> <out_file>\n");
        printf(
            "usage3 : pcp_file_crypt <url|program_id> <parameter_list> "
            "<in_file> <out_file>\n");
        printf("\n");

        printf(
            "example1 : pcp_file_crypt crypt encrypt whole_encrypt.params\n");
        printf(
            "example2 : pcp_file_crypt encrypt BK.SEED test.dat "
            "test.dat.enc\n");
        printf(
            "example3 : pcp_file_crypt crypt "
            "\"(key=(1=(name=test)(columns=1)))(mode=(crypt=encrypt))\" "
            "plain.dat enc.dat\n");

        return 1;
    }

    dgt_sint32 rtn = 0;

    PccFileCryptor cryptor;
    if (argc == 5) {  // usage2
        if (strncmp(argv[1], "encrypt", 7) == 0 ||
            strncmp(argv[1], "decrypt", 7) == 0) {
            dgt_schar param_list[1024];
            memset(param_list, 0, 1024);
            sprintf(param_list,
                    "(key=(1=(name=%s)(columns=1)))(mode=(crypt=%s)(overwrite_"
                    "flag=on))(session=(program_id=pcp_file_crypt))",
                    argv[2], argv[1]);
            rtn = cryptor.crypt(-1, param_list, argv[3], argv[4]);
        } else {  // usage3
            cryptor.setProgramName(argv[1]);
            rtn = cryptor.crypt(-1, argv[2], argv[3], argv[4]);
        }
    } else {  // usage1
        cryptor.setProgramName(argv[1]);
        cryptor.setCryptMode(argv[2]);
        rtn = cryptor.crypt(-1, argv[3], 0, 0);
    }
    if (rtn < 0) {
        if (rtn == -30118) {
            printf("- crypt failed:%d:%s\n", rtn, "not encrypted file");
        } else {
            printf("- crypt failed:%d:%s\n", rtn, cryptor.errString());
        }
    } else {
        printf("Crypt file successfully..\n");
        printf("- output buffer length => [%lld]\n", cryptor.outBufLen());
    }

    return rtn;
}
