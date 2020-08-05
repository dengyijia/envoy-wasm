#include "http_parser.h"
#include <ctype.h>

std::string percentDecode(std::string encoded) {
  std::string decoded;
  decoded.reserve(encoded.size());
  for (size_t i = 0; i < encoded.size(); ++i) {
    char ch = encoded[i];
    if (ch == '%' && i + 2 < encoded.size()) {
      const char& hi = encoded[i + 1];
      const char& lo = encoded[i + 2];
      if (isdigit(hi)) {
        ch = hi - '0';
      } else {
        ch = toupper(hi) - 'A' + 10;
      }

      ch *= 16;
      if (isdigit(lo)) {
        ch += lo - '0';
      } else {
        ch += toupper(lo) - 'A' + 10;
      }
      i += 2;
    }
    decoded.push_back(ch);
  }
  return decoded;
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
      std::string key = percentDecode(param.substr(start, start + equal));
      std::string val = percentDecode(param.substr(start + equal + 1, end));
      params.emplace(key, val);
    } else {
      std::string key = percentDecode(param.substr(start, end));
      params.emplace(key, "");
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


