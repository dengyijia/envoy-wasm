#include "common.h"

using QueryParams = std::unordered_map<std::string, std::string>;

std::string percentDecode(std::string encoded);

QueryParams parsePath(std::string path);

QueryParams parseBody(std::string body);

QueryParams parseCookie(std::string cookie);

std::string toString(QueryParams params);


