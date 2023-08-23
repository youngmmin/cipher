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
#include <time.h>

#include <cstdlib>

#include "PcbFileCryptorParam.h"
#include "PccFileCryptor.h"
#include "PccHeaderManager.h"

#ifdef _WIN32
#define PATH_SEPARATOR '\\'
#else
#define PATH_SEPARATOR '/'
#endif

void printHelp() {
    printf("\nUsage: pcb_filecryptor [OPTION] [ADDITIONAL OPTIONS]\n\n");

    printf("General Options:\n");
    printf("  -h, --help\t\tDisplay this help message and exit\n");
    printf("  -q, --quiet\t\tSuppress output messages\n\n");

    printf("Required Options (Choose only one):\n");
    printf("  -e, --encrypt\t\tEncrypt mode\n");
    printf("  -d, --decrypt\t\tDecrypt mode\n");
    printf(
        "  -p, --parameter [parameter_string]\tParameter mode. Format: "
        "\"(file=(in=plain.dat)...)\"\n");
    printf(
        "  -c, --check [path]\t\tHeader Check mode. Check the header of the "
        "specified file.\n\n");

    printf("Additional Options (applicable for encrypt/decrypt modes):\n");
    printf("  -in      [path]\tInput file or directory path\n");
    printf("  -out     [path]\tOutput file or directory path\n");
    printf("  -key     [name]\tSpecify the 'enc_col_name' value\n");
    printf("  -threads [number]\tNumber of threads to be used\n");

    printf("Examples:\n");
    printf(
        "  pcb_filecryptor -e -in plain.dat -out plain.dat.enc -key "
        "aria_256_b64\n");
    printf(
        "  pcb_filecryptor --quiet --decrypt -in plain.dat.enc -out "
        "plain.dat.dec "
        "-key "
        "aria_256_b64\n");
    printf("  pcb_filecryptor -q -p \"(file=(in=plain.dat)...)\"\n");
    printf("  pcb_filecryptor -c plain.dat\n\n");

    printf("Note:\n");
    printf("  - You must choose only one option from the Required Options.\n");
    printf(
        "  - Based on your choice, you might need to specify additional "
        "options.\n\n");
}

int main(int argc, char *argv[]) {
    int i;
    int has_encrypt = 0, has_decrypt = 0, has_param = 0, has_check = 0,
        has_in = 0, has_out = 0, has_key = 0;
    int is_quiet = 0;

    PcbFileCryptorParam *param = new PcbFileCryptorParam();

    if (argc < 2) {
        fprintf(stderr,
                "[ERROR] Invalid arguments. Use -h or --help for usage "
                "details.\n\n");
        return 0;
    }

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printHelp();
            return 0;
        }
        if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) {
            is_quiet = 1;
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
        if (strcmp(argv[i], "-threads") == 0) {
            if (i + 1 < argc) {
                i++;  // Skip next argument
                has_key = 1;
                param->setThreads(argv[i]);
                continue;
            } else {
                fprintf(stderr,
                        "ERROR: -threads or option requires an argument\n");
                return 1;
            }
        }
    }

    if ((has_encrypt + has_decrypt + has_check + has_param) > 1) {
        fprintf(stderr,
                "ERROR: Only one option among -e, -d, -p, -c can be set.\n");
        printHelp();
        return 1;  // failure
    } else if ((has_encrypt + has_decrypt + has_check + has_param) == 0) {
        fprintf(
            stderr,
            "ERROR: At least one option among -e, -d, -p, -c must be set.\n");
        printHelp();
        return 1;  // failure
    }

    // Ensure that if encryption or decryption is chosen, the necessary options
    // (-in, -out, and -key) are also provided.
    if ((has_encrypt || has_decrypt) && !(has_in && has_out && has_key)) {
        fprintf(stderr, "ERROR: -in, -out, and -key options are required\n");
        printHelp();
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

        struct timespec start_time, end_time;
        clock_gettime(CLOCK_REALTIME, &start_time);

        int rtn = cryptor.crypt(-1, param_list, 0, 0);

        clock_gettime(CLOCK_REALTIME, &end_time);

        double elapsed_time_ms =
            (end_time.tv_sec - start_time.tv_sec) * 1000.0 +
            (end_time.tv_nsec - start_time.tv_nsec) / 1000000.0;

        // Handle the result of the operation.
        if (rtn < 0) {
            printf("ERROR: crypt failed. error code '%d'\n", rtn);
        } else {
            if (!is_quiet) {
                if (param->getMode() == PcbFileCryptorParam::FCB_MODE_ENCRYPT) {
                    printf("INFO: '%s' to '%s' (encrypted successfully). ",
                           param->getInFile(), param->getOutFile());
                } else if (param->getMode() ==
                           PcbFileCryptorParam::FCB_MODE_DECRYPT) {
                    printf("INFO: '%s' to '%s' (decrypted successfully). ",
                           param->getInFile(), param->getOutFile());
                } else if (param->getMode() ==
                           PcbFileCryptorParam::FCB_MODE_PARAMETER) {
                    printf("INFO: parameter executed successfully. ");
                }
                printf("elapse time '%.0f' ms\n", elapsed_time_ms);
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
