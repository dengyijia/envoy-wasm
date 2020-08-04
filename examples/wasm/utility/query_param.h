#include "common.h"

using QueryParams = std::unordered_map<std::string, std::string>;

QueryParams parsePath(std::string path);

QueryParams parseBody(std::string body);

QueryParams parseCookie(std::string cookie);

std::string toString(QueryParams params);


