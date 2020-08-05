#include "query_param.h"

std::string urlDecode(std::string value) {


}

QueryParams parseParameters(std::string data, size_t start,
                            std::string delim = "&", std::string eq = "=") {
  QueryParams params;

  while (start < data.size()) {
    size_t end = data.find(delim, start);
    if (end == std::string::npos) {
      end = data.size();
    }
    std::string param = data.substr(start, end - start);

    const size_t equal = param.find(eq);
    if (equal != std::string::npos) {
      params.emplace(param.substr(start, start + equal),
                     param.substr(start + equal + 1, end));
    } else {
      params.emplace(param.substr(start, end), "");
    }

    start = end + 1;
  }

  return params;
}

QueryParams parsePath(std::string path) {
  size_t start = path.find('?');
  if (start == std::string::npos) {
    QueryParams params;
    return params;
  }
  start++;
  return parseParameters(path, start);
}

QueryParams parseBody(std::string body) {
  return parseParameters(body, 0);
}

QueryParams parseCookie(std::string cookie) {
  return parseParameters(cookie, 0, "; ");
}

std::string toString(QueryParams params) {
  std::string str;
  for (auto param : params) {
    str += param.first + " -> " + param.second;
  }
  return str;
}


