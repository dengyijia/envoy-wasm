#include "sqli.h"

int detectSQLi(std::string input) {
  struct libinjection_sqli_state state;
  char* input_char_str = const_cast<char*>(input.c_str());
  libinjection_sqli_init(&state, input_char_str, input.length(), FLAG_NONE);
  return libinjection_is_sqli(&state);
}


bool detectSQLiOnParams(QueryParams params, bool include, Keys keys, std::string* log) {
  Keys keys_to_inspect;
  if (include) {
    keys_to_inspect = keys;
  } else {
    for (auto param : params) {
      if (keys.find(param.first) == keys.end()) {
        keys_to_inspect.insert(param.first);
      }
    }
  }
  // detect sql injection in configured headers
  for (auto key : keys_to_inspect) {
    auto param = params.find(key);
    if (param == params.end()) {
      continue;
    }
    if (detectSQLi(param->second) || detectSQLi(param->first)) {
      return true;
    }
    log->append("key [" + key + "] passed sqli detection\n");
  }
  return false;
}
