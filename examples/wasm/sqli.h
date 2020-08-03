// NOLINT(namespace-envoy)
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>

#include "src/libinjection.h"
#include "src/libinjection_sqli.h"

#include "query_param.h"

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
bool detectSQLiOnParams(QueryParams params, bool include, std::vector<std::string> keys);
