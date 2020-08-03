#include "sqli.h"

inline bool exists(std::string val, std::vector<std::string> vec) {
  return std::find(vec.begin(), vec.end(), val) != vec.end();
}

int detectSQLi(std::string input) {
  struct libinjection_sqli_state state;
  char* input_char_str = const_cast<char*>(input.c_str());
  libinjection_sqli_init(&state, input_char_str, input.length(), FLAG_NONE);

  return libinjection_is_sqli(&state);
}

bool detectSQLiOnParams(QueryParams params, bool include, std::vector<std::string> keys) {
  // find configured headers to detect sql injection
  std::vector<std::string> keys_to_inspect;
  if (include) {
    keys_to_inspect = keys;
  } else {
    for (auto param : params) {
      if (exists(param.first, keys)) {
        keys_to_inspect.push_back(param.first);
      }
    }
  }
  // detect sql injection in configured headers
  for (auto key : keys_to_inspect) {
    auto param = params.find(key);
    if (param == params.end()) {
      continue;
    }
    if (detectSQLi(param->second)) {
      return true;
    }
  }
  return false;
}
