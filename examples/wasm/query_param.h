// NOLINT(namespace-envoy)
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>

using QueryParams = std::unordered_map<std::string, std::string>;

QueryParams parsePath(std::string path);

QueryParams parseBody(std::string body);

QueryParams parseCookie(std::string cookie);

std::string toString(QueryParams params);


