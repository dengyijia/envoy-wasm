#include "common.h"
#include "query_parser.h"

#include "src/libinjection.h"
#include "src/libinjection_sqli.h"


int detectSQLi(std::string input);

/**
 * Detect SQL injection on given parameter pairs with configuration
 * Input
 *  - params: a map of param key value pairs
 *  - include: a boolean
 *      if true, given keys are the only keys to detect
 *      if false, given keys are all but the given keys will be detected
 *  - keys: a vector of keys to be included or excluded
 *  - part: name of the param part (header/body/cookie/path)
 * Output
 *   true if a SQL injection is detected, false if not
 */
bool detectSQLiOnParams(QueryParams params, bool include, Keys keys, std::string* log);
