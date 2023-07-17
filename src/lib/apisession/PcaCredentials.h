/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcaCredentials
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 4. 24
 *   Description        :       credentials for key server connection
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCA_CREDENTIALS_H
#define PCA_CREDENTIALS_H


#include "DgcObject.h"


class PcaCredentials : public DgcObject {
  private:
	static const dgt_sint32	PCD_ERR_PARSE_ERROR		= -30501;
	static const dgt_sint32	PCD_ERR_INVALID_CREDENTIALS	= -30502;

	dgt_schar	SvcName[33]; // soha service name
	dgt_schar	UserID[33];  // soha user id
	dgt_schar	Password[33]; // soha password
	dgt_schar	Credentials[1024]; // credentials
	dgt_schar	KeySeed[33]; // key seed
	dgt_schar	ErrMsg[256]; // error message
	//
	// added by chchung, 2012.11.01, to get session attributes from credentials
	//
	dgt_schar	IP[65]; // IP
	dgt_schar	MAC[65]; // MAC
	dgt_schar	InstanceName[33]; // instance name
	dgt_schar	DbName[33]; // database name
	dgt_schar	DbUser[33]; // database user
	dgt_schar	OsUser[33]; // os user
	dgt_schar	Program[129]; // program
	dgt_schar	OrgUserID[33]; // org user id
	dgt_schar	SvcHome[129]; // soha home

	inline dgt_void cleanAttrs()
	{
		memset(SvcName, 0, 33);
		memset(UserID, 0, 33);
		memset(Password, 0, 33);
		memset(Credentials, 0, 1024);
		//
	        // added by chchung, 2012.11.01, to get session attributes from credentials
		//
		memset(IP, 0, 65);
		memset(MAC, 0, 65);
		memset(InstanceName, 0, 33);
		memset(DbName, 0, 33);
		memset(DbUser, 0, 33);
		memset(OsUser, 0, 33);
		memset(Program, 0, 129);
		memset(OrgUserID, 0, 33);
		memset(SvcHome, 0, 129);
	};

	dgt_void generateKey(const dgt_schar* credentials_pw);
  protected:
  public:
	PcaCredentials();
	virtual ~PcaCredentials();

	inline dgt_schar* svcName() { return SvcName; };
	inline dgt_schar* userID() { return UserID; };
	inline dgt_schar* password() { return Password; };
	inline dgt_schar* credentials() { return Credentials; };
	inline dgt_schar* errMsg() { return ErrMsg; };
	//
        // added by chchung, 2012.11.01, to get session attributes from credentials
        //
	inline dgt_schar* svcHome() { return SvcHome; };
	inline dgt_schar* ip() { return IP; };
	inline dgt_schar* mac() { return MAC; };
	inline dgt_schar* instanceName() { return InstanceName; };
	inline dgt_schar* dbName() { return DbName; };
	inline dgt_schar* dbUser() { return DbUser; };
	inline dgt_schar* osUser() { return OsUser; };
	inline dgt_schar* program() { return Program; };
	inline dgt_schar* orgUserID() { return OrgUserID; };
	inline dgt_void setSvcHome(const dgt_schar* val) { strncpy(SvcHome, val, 128); };
	inline dgt_void setIP(const dgt_schar* val) { strncpy(IP, val, 64); };
	inline dgt_void setMAC(const dgt_schar* val) { strncpy(MAC, val, 64); };
	inline dgt_void setInstanceName(const dgt_schar* val) { strncpy(InstanceName, val, 32); };
	inline dgt_void setDbName(const dgt_schar* val) { strncpy(DbName, val, 32); };
	inline dgt_void setDbUser(const dgt_schar* val) { strncpy(DbUser, val, 32); };
	inline dgt_void setOsUser(const dgt_schar* val) { strncpy(OsUser, val, 32); };
	inline dgt_void setProgram(const dgt_schar* val) { strncpy(Program, val, 128); };
	inline dgt_void setOrgUserID(const dgt_schar* val) { strncpy(OrgUserID, val, 32); };

	dgt_sint32 generate(const dgt_schar* svc_name, const dgt_schar* user_id, const dgt_schar* password, const dgt_schar* credentials_pw=0);
	dgt_sint32 parse(const dgt_schar* credentials,const dgt_schar* credentials_pw=0);
};


#endif
