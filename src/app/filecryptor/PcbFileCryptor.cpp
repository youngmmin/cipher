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
#include "PccFileCryptor.h"
#include "PccHeaderManager.h"

#ifdef _WIN32
#define PATH_SEPARATOR '\\'
#else
#define PATH_SEPARATOR '/'
#endif

void print_usage() {
    printf("\n");
    printf("Usage: pcb_filecryptor [options]\n");
    printf("options:\n");
    printf("  (REQUIRED - select exactly one)\n");
    printf(
        "  -e, --encrypt			Encrypt the input file (requires: -in, "
        "-out, "
        "-key)\n");
    printf(
        "  -d, --decrypt			Decrypt the input file (requires: -in, "
        "-out, "
        "-key)\n");
    printf(
        "  -p, --parameter \"<parameter>\"	Execute the encryption or "
        "decryption action "
        "as set in the parameter (requires: none)\n");
    printf(
        "  -c, --check			Check if the input file is encrypted "
        "(requires: "
        "-in)\n");
    printf("\n");

    printf("  (REQUIRED - if -e, -d, or -c is selected)\n");
    printf("  -in <file>		Specify the input file\n");
    printf("  -out <file>		Specify the output file\n");
    printf(
        "  -key <name>		Specify the 'enc_col_name' value "
        "in petra "
        "cipher "
        "kms\n");
    printf("\n");
    printf(
        "  -v, --verbose		Display encryption/decryption result "
        "messages\n");
    printf("  -h, --help		Show this help message\n");
    printf("\n");
    printf("\n");
}

int main(int argc, char *argv[]) {
    const char *separator_pos = strrchr(argv[0], PATH_SEPARATOR);
    const char *binary_name = separator_pos ? separator_pos + 1 : argv[0];

    const char *user = getenv("USER");

    PcbFileCryptorParam *param = new PcbFileCryptorParam();
    param->setProgramName(binary_name);
    param->setUser(user);

    int i;
    int has_encrypt = 0, has_decrypt = 0, has_param = 0, has_check = 0,
        has_in = 0, has_out = 0, has_key = 0;
    int has_dump = 0;

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage();
            return 0;
        }
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            has_dump = 1;
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
        if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--parameter") == 0) {
            if (i + 1 < argc) {
                i++;  // Skip next argument
                has_param = 1;
                param->setParameter(argv[i]);
                param->setParameterMode();
                continue;
            } else {
                fprintf(stderr, "ERROR: -in option requires an argument\n");
                return 1;
            }
            continue;
        }
        if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--check") == 0) {
            has_check = 1;
            i++;  // Skip next argument
            param->setInFile(argv[i]);
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
        if (strcmp(argv[i], "-key") == 0) {
            if (i + 1 < argc) {
                i++;  // Skip next argument
                has_key = 1;
                param->setKeyName(argv[i]);
                continue;
            } else {
                fprintf(stderr, "ERROR: -key or option requires an argument\n");
                return 1;
            }
        }
    }

    if ((has_encrypt + has_decrypt + has_check + has_param) > 1) {
        fprintf(stderr,
                "ERROR: Only one option among -e, -d, -p, -c can be set.\n");
        print_usage();
        return 1;  // failure
    } else if ((has_encrypt + has_decrypt + has_check + has_param) == 0) {
        fprintf(
            stderr,
            "ERROR: At least one option among -e, -d, -p, -c must be set.\n");
        print_usage();
        return 1;  // failure
    }

    // Ensure that if encryption or decryption is chosen, the necessary options
    // (-in, -out, and -key) are also provided.
    if ((has_encrypt || has_decrypt) && !(has_in && has_out && has_key)) {
        fprintf(stderr, "ERROR: -in, -out, and -key options are required\n");
        print_usage();
        return 1;
    }

    // If either -p or -check option is chosen, warn the user that -in,
    // -out, and -key options are not utilized.
    if ((has_param || has_check) && (has_in || has_out || has_key)) {
        fprintf(stderr, "WARNNING: -in, -out, and -key options are not used\n");
    }

    // If encryption, decryption, or parameter setting is chosen:
    if (has_encrypt || has_decrypt || has_param) {
        char param_list[2048];

        // Retrieve the parameter string for the chosen operation.
        param->getParameterString(param_list, sizeof(param_list));

        // Uncomment below line to print the parameter string for debugging
        // purposes. printf("Parameter: %s\n", param_list);

        // Initialize the file cryptor and perform the chosen operation.
        PccFileCryptor cryptor;
        int rtn = cryptor.crypt(-1, param_list, 0, 0);

        // Handle the result of the operation.
        if (rtn < 0) {
            printf("ERROR: crypt failed. error code '%d'\n", rtn);
        } else {
            // If the -dump flag is provided, print the result of the operation.
            if (has_dump) {
                if (param->getMode() == PcbFileCryptorParam::FCB_MODE_ENCRYPT) {
                    printf("INFO: '%s' to '%s' (encrypted successfully).\n",
                           param->getInFile(), param->getOutFile());
                } else if (param->getMode() ==
                           PcbFileCryptorParam::FCB_MODE_DECRYPT) {
                    printf("INFO: '%s' to '%s' (decrypted successfully).\n",
                           param->getInFile(), param->getOutFile());
                } else if (param->getMode() ==
                           PcbFileCryptorParam::FCB_MODE_PARAMETER) {
                    printf("INFO: parameter executed successfully.\n");
                }
            }
        }
        // If the check operation is chosen, determine if the file is encrypted.
    } else if (has_check) {
        PccHeaderManager header_manager;

        // Set the desired header flag.
        header_manager.setHeaderFlag("V2on");

        // Check if the file is encrypted.
        int rtn = PccHeaderManager::isEncrypted(param->getInFile());

        // Handle the result of the check.
        if (rtn < 0) {
            printf("ERROR: check failed:%d\n", rtn);
        } else if (rtn == 0) {
            printf("INFO: '%s' is not encrypted\n", param->getInFile());
        } else {
            printf("INFO: '%s' is encrypted\n", param->getInFile());
        }
    }

    return 0;
}
