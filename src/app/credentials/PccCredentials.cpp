/*******************************************************************
 *   File Type          :       main file
 *   Classes            :       PccCredentials
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 4. 25
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "DgcAuthPasswd.h"
#include "PcaCredentials.h"

template <class C>
class PccAutoPtr {
   private:
    C* Pointer;

   public:
    PccAutoPtr(C* ptr = 0) : Pointer(ptr){};
    ~PccAutoPtr() { delete Pointer; };
};

class PccCmdOption {
   private:
    static const dgt_sint32 DGC_MAX_CMD_OPTIONS = 500;
    typedef struct {
        const dgt_schar* name;
        const dgt_schar* value;
    } dgt_cmd_option;

    dgt_cmd_option Options[DGC_MAX_CMD_OPTIONS];
    dgt_sint32 NumOptions;

   protected:
   public:
    PccCmdOption(dgt_sint32 argc, dgt_schar** argv) {
        dgt_sint32 curr_option = -1;
        NumOptions = 0;
        for (dgt_sint32 i = 0; i < argc && i < DGC_MAX_CMD_OPTIONS; i++) {
            if (argv[i][0] == '-') {
                Options[curr_option = NumOptions++].name = argv[i] + 1;
                Options[curr_option].value = "";
            } else {
                if (curr_option >= 0) Options[curr_option].value = argv[i];
                curr_option = -1;
            }
        }
    };
    ~PccCmdOption(){};

    inline const dgt_schar* optionValue(const dgt_schar* option_name) {
        for (dgt_sint32 i = 0; i < NumOptions; i++) {
            if (!strcasecmp(option_name, Options[i].name))
                return Options[i].value;
        }
        return 0;
    }
};

class PccCmd {
   private:
   protected:
    PccCmdOption& CmdOption;

   public:
    PccCmd(PccCmdOption& cmd_option) : CmdOption(cmd_option){};
    virtual ~PccCmd(){};
    virtual dgt_sint32 run() = 0;
};

class PccCmdHelp : public PccCmd {
   private:
   protected:
   public:
    PccCmdHelp(PccCmdOption& cmd_option) : PccCmd(cmd_option){};
    virtual ~PccCmdHelp(){};

    virtual dgt_sint32 run() {
        dg_print("\npcp_credentials help\n");
        dg_print(
            "pcp_credentials generate -svc demo -user dgadmin -password abc "
            "-key this_is_key "
            "-[svc_home|ip|mac|instance|db_name|db_user|os_user|program|org_"
            "user]\n");
        dg_print(
            "pcp_credentials parse -key this_is_key -credentials "
            "hdfdsf123+93dkf\n");
        return 0;
    };
};

class PccCmdGenerate : public PccCmd {
   private:
   protected:
   public:
    PccCmdGenerate(PccCmdOption& cmd_option) : PccCmd(cmd_option){};
    virtual ~PccCmdGenerate(){};

    virtual dgt_sint32 run() {
        const dgt_schar* svc = CmdOption.optionValue("svc");
        const dgt_schar* user = CmdOption.optionValue("user");
        const dgt_schar* pw = CmdOption.optionValue("password");
        const dgt_schar* key = CmdOption.optionValue("key");
        if (svc == 0 || user == 0) {
            printf("no svc or user\n");
            return -1;
        }
        dgt_schar passwd[33];
        if (pw == 0) {
            memset(passwd, 0, 33);
            if (UI_UTIL_read_pw_string(passwd, 32, "password: ", 0)) {
                printf("UI_UTIL_read_pw_string failed\n");
                return -1;
            }
            pw = passwd;
        }
        PcaCredentials pc;
        //
        // added by chchung 2012.11.2 for adding open_session attributes into
        // credentials
        //
        const dgt_schar* val;
        if ((val = CmdOption.optionValue("svc_home"))) pc.setSvcHome(val);
        if ((val = CmdOption.optionValue("ip"))) pc.setIP(val);
        if ((val = CmdOption.optionValue("mac"))) pc.setMAC(val);
        if ((val = CmdOption.optionValue("instance"))) pc.setInstanceName(val);
        if ((val = CmdOption.optionValue("db_name"))) pc.setDbName(val);
        if ((val = CmdOption.optionValue("db_user"))) pc.setDbUser(val);
        if ((val = CmdOption.optionValue("os_user"))) pc.setOsUser(val);
        if ((val = CmdOption.optionValue("program"))) pc.setProgram(val);
        if ((val = CmdOption.optionValue("org_user"))) pc.setOrgUserID(val);
        dgt_sint32 rtn;
        if ((rtn = pc.generate(svc, user, pw, key))) {
            printf("generate failed:%s\n", pc.errMsg());
            return rtn;
        }
        printf("\ncredentials => %s\n", pc.credentials());
        return 0;
    };
};

class PccCmdParse : public PccCmd {
   private:
   protected:
   public:
    PccCmdParse(PccCmdOption& cmd_option) : PccCmd(cmd_option){};
    virtual ~PccCmdParse(){};

    virtual dgt_sint32 run() {
        const dgt_schar* key = CmdOption.optionValue("key");
        const dgt_schar* credentials = CmdOption.optionValue("credentials");
        if (credentials == 0) {
            printf("no credentials\n");
            return -1;
        }
        PcaCredentials pc;
        dgt_sint32 rtn;
        if ((rtn = pc.parse(credentials, key))) {
            printf("parse failed:%s\n", pc.errMsg());
            return rtn;
        }
        printf("\ncredentials => %s\n", pc.credentials());
        printf("svc => %s\n", pc.svcName());
        printf("user => %s\n", pc.userID());
        printf("password => %s\n", pc.password());
        if (*pc.svcHome()) printf("svc home => %s\n", pc.svcHome());
        if (*pc.ip()) printf("IP => %s\n", pc.ip());
        if (*pc.mac()) printf("MAC => %s\n", pc.mac());
        if (*pc.instanceName())
            printf("Instance Name => %s\n", pc.instanceName());
        if (*pc.dbName()) printf("DB Name => %s\n", pc.dbName());
        if (*pc.dbUser()) printf("DB User => %s\n", pc.dbUser());
        if (*pc.osUser()) printf("OS User => %s\n", pc.osUser());
        if (*pc.program()) printf("Program => %s\n", pc.program());
        if (*pc.orgUserID()) printf("ORG User ID => %s\n", pc.orgUserID());
        return 0;
    };
};

class PccCredentials {
   private:
    dgt_schar* Cmd;
    PccCmdOption CmdOption;

   protected:
   public:
    PccCredentials(dgt_sint32 argc, dgt_schar** argv)
        : Cmd(argv[1]), CmdOption(argc, argv){};
    ~PccCredentials(){};

    dgt_void runCommand() {
        PccCmd* cmd = 0;
        if (!strcasecmp(Cmd, "help")) {
            cmd = new PccCmdHelp(CmdOption);
        } else if (!strcasecmp(Cmd, "generate")) {
            cmd = new PccCmdGenerate(CmdOption);
        } else if (!strcasecmp(Cmd, "parse")) {
            cmd = new PccCmdParse(CmdOption);
        } else {
            dg_print("unknown command[%s]\n", Cmd);
            return;
        }
        PccAutoPtr<PccCmd> cmd_ptr(cmd);
        cmd->run();
    };
};

int main(dgt_sint32 argc, dgt_schar** argv) {
    if (argc < 2) {
        dg_print("usage: pcp_credentials help\n");
        exit(1);
    }
    PccCredentials mgr(argc, argv);
    mgr.runCommand();
}
