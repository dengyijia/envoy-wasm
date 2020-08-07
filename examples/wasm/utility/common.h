// NOLINT(namespace-envoy)
#include <string>
#include <unordered_map>
#include <unordered_set>

#pragma once

const std::string URLENCODED = "application/x-www-form-urlencoded";

using Keys = std::unordered_set<std::string>;
using QueryParams = std::unordered_map<std::string, std::string>;

std::string toString(QueryParams params) {
  std::string str;
  for (auto param : params) {
    str += param.first + " -> " + param.second;
  }
  return str;
}


