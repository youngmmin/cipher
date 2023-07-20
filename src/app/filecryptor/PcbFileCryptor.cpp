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
#include <cstdlib>

#include "PcbFileCryptorParam.h"

void print_usage() {
    printf("\n");
    printf("Usage: pcb_filecryptor [options]\n");
    printf("options:\n");
    printf("  (REQUIRED - select exactly one)\n");
    printf(
        "  -e, --encrypt		Encrypt the input file (requires: -in, -out, "
        "-keyname)\n");
    printf(
        "  -d, --decrypt		Decrypt the input file (requires: -in, -out, "
        "-keyname)\n");
    printf(
        "  -c, --check		Check if the input file is encrypted (requires: "
        "-in)\n");
    printf("\n");

    printf("  (REQUIRED - if -e, -d, or -c is selected)\n");
    printf("  -in <file>		Specify the input file\n");
    printf("  -out <file>		Specify the output file\n");
    printf(
        "  -keyname <name>	Specify the 'enc_col_name' value in petra cipher "
        "kms\n");
    printf("\n");
    printf("  -h, --help		Show this help message\n");
}

int main(int argc, char *argv[]) {
    const char *user = getenv("USER");

    PcbFileCryptorParam *param = new PcbFileCryptorParam();
    param->setUser(user);

    int i;
    int has_encrypt = 0, has_decrypt = 0, has_check = 0, has_in = 0,
        has_out = 0, has_keyname = 0;

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage();
            return 0;
        }
        if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--encrypt") == 0) {
            has_encrypt = 1;
            param->setEncryptMode();
            continue;
        }
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--decrypt") == 0) {
            has_decrypt = 1;
            param->setDecryptMode();
            continue;
        }
        if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--check") == 0) {
            has_check = 1;
            param->setCheckMode();
            continue;
        }
        if (strcmp(argv[i], "-in") == 0) {
            if (i + 1 < argc) {
                i++;  // Skip next argument
                has_in = 1;
                param->setInFile(argv[i]);
                continue;
            } else {
                fprintf(stderr, "ERROR: -in option requires an argument\n");
                return 1;
            }
        }
        if (strcmp(argv[i], "-out") == 0) {
            if (i + 1 < argc) {
                i++;  // Skip next argument
                has_out = 1;
                param->setOutFile(argv[i]);
                continue;
            } else {
                fprintf(stderr, "ERROR: -out option requires an argument\n");
                return 1;
            }
        }
        if (strcmp(argv[i], "-keyname") == 0) {
            if (i + 1 < argc) {
                printf("Encryption column name: %s\n", argv[i + 1]);
                i++;  // Skip next argument
                has_keyname = 1;
                param->setKeyName(argv[i]);
                continue;
            } else {
                fprintf(stderr,
                        "ERROR: -keyname option requires an argument\n");
                return 1;
            }
        }
    }

    if ((has_encrypt + has_decrypt + has_check) > 1) {
        fprintf(stderr,
                "ERROR: Only one option among -e, -d, -c can be set.\n");
        print_usage();
        return 1;  // failure
    } else if ((has_encrypt + has_decrypt + has_check) == 0) {
        fprintf(stderr,
                "ERROR: At least one option among -e, -d, -c must be set.\n");
        print_usage();
        return 1;  // failure
    }

    if ((has_encrypt || has_decrypt) && !(has_in && has_out && has_keyname)) {
        fprintf(stderr,
                "ERROR: -in, -out, and -keyname options are required\n");
        print_usage();
        return 1;
    }

    if (has_check && !(has_in)) {
        fprintf(stderr, "ERROR: -in option is required\n");
        print_usage();
        return 1;
    }

    return 0;
}
