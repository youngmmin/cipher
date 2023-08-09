/*******************************************************************
 *   File Type          :       main file
 *   Classes            :       RegexMatcher
 *   Implementor        :       dhkim
 *   Create Date        :       2023. 08. 09
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/

#include <regex.h>
#include <stdio.h>

#include <cstring>

#include "DgcObject.h"

class PcbRegexpMatcher : public DgcObject {
   private:
    regex_t regex;
    bool isCompiled;

   public:
    PcbRegexpMatcher() : isCompiled(false) {}

    ~PcbRegexpMatcher() {
        if (isCompiled) {
            regfree(&regex);
        }
    }

    bool compile(const char* pattern) {
        if (isCompiled) {
            regfree(&regex);
        }

        int status = regcomp(&regex, pattern, REG_EXTENDED);
        if (status != 0) {
            char errorMessage[256];
            regerror(status, &regex, errorMessage, sizeof(errorMessage));
            fprintf(stderr, "Regex error: %s\n", errorMessage);
            return false;
        }

        isCompiled = true;
        return true;
    }

    bool matches(const char* text) {
        if (!isCompiled) {
            fprintf(stderr, "Regex not compiled.\n");
            return false;
        }

        return regexec(&regex, text, 0, NULL, 0) == 0;
    }
};

void printExamples() {
    printf("Option examples for -reg \"<regexp>\":\n\n");

    printf("General Patterns:\n");
    printf("\t- any number: \"^[0-9]+$\"\n");
    printf("\t- any alphabetic string: \"^[a-zA-Z]+$\"\n\n");

    printf("Date Formats:\n");
    printf(
        "\t- YYYYMMDD: "
        "\"^([0-9]{4})(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])$\"\n");
    printf(
        "\t- YYYY-MM-DD: "
        "\"^([0-9]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$\"\n\n");

    printf("File Extensions:\n");
    printf("\t- .jpg: \".*\\.jpg$\"\n\n");
}

void printHelp() {
    printf("Usage:\n");
    printf(
        "  PatternValidator -reg \"<regexp>\" -str \"<example string>\"\n\n");
    printf("Options:\n");
    printf("  -e, --example   Display regular expression examples.\n");
    printf("  -h, --help      Display this help message.\n\n");
}

int main(int argc, char* argv[]) {
    char* pattern = NULL;
    char* testString = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-reg") == 0 && i + 1 < argc) {
            pattern = argv[++i];
        } else if (strcmp(argv[i], "-str") == 0 && i + 1 < argc) {
            testString = argv[++i];
        } else if (strcmp(argv[i], "-e") == 0 ||
                   strcmp(argv[i], "--example") == 0) {
            printExamples();
            return 0;
        } else if (strcmp(argv[i], "-h") == 0 ||
                   strcmp(argv[i], "--help") == 0) {
            printHelp();
            return 0;
        }
    }

    if (!pattern || !testString) {
        fprintf(stderr,
                "[ERROR] Invalid arguments. Use -h or --help for usage "
                "details.\n\n");
        return 1;
    }

    PcbRegexpMatcher* matcher = new PcbRegexpMatcher();
    if (!matcher->compile(pattern)) {
        delete matcher;
        return 1;
    }

    if (matcher->matches(testString)) {
        printf("[MATCHED] The string matches the pattern.\n\n");
    } else {
        printf("[NOT MATCHED] The string does not match the pattern.\n\n");
    }

    delete matcher;
    return 0;
}