#ifndef SUNDEC_H
#define SUNDEC_H

#include "SunGcrypt.h"
#include "FileOps.h"
#include <string>

using std::string;

/* Input parameter definitions */
#define L_NUM_PARAMS 3
#define D_NUM_PARAMS 4
#define D_OPT "-d"
#define L_OPT "-l"

/* Error code definitions */
typedef enum
{
	ERR_NUM_PARAMS		= 1,
	ERR_OPT			= 2,
	ERR_NO_FILE		= 3,
     ERR_EXT             = 4,
     ERR_FILE_EXISTS     = 33,
} parseErrorTypes;	

/* Sundec Class */
class Sundec
{
public:
     int Decrypt(int numParams, char** params);

private:
     int Parse(int numParams, char** params);
     void ParseErrorMsg(int errCode);

     string inputFileName;
     string outputFileName;
     string type;
     string port;
     string key;

     SunGcrypt gcrypt;
     FileOps fOps;
     bool localMode;
};

#endif //SUNDEC_H