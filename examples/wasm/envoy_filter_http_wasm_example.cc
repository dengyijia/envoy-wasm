// NOLINT(namespace-envoy)
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>

#include "proxy_wasm_intrinsics.h"
#include "nlohmann/json.hpp"
#include "src/libinjection.h"
#include "src/libinjection_sqli.h"

#include "examples/wasm/config.h"

using QueryParams = std::map<std::string, std::string>;

/*
 * Check if the string val exists in the vector vec
 */
inline bool exists(std::string val, std::vector<std::string> vec) {
  return std::find(vec.begin(), vec.end(), val) != vec.end();
}

/*
 * Methods for parsing query parameters
 */
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

/*
 * Detect SQL injection on given input string
 */
bool detectSQLi(std::string input, std::string key, std::string part) {
  struct libinjection_sqli_state state;
  char* input_char_str = const_cast<char*>(input.c_str());
  libinjection_sqli_init(&state, input_char_str, input.length(), FLAG_NONE);

  int issqli = libinjection_is_sqli(&state);
  if (issqli) {
    std::string response_body = "SQL injection detected";
    std::string response_log = "SQLi at " + part + "->" + key + ", fingerprint: "
        + std::string(state.fingerprint);
    sendLocalResponse(403, response_log, response_body, {});
    return true;
  }
  LOG_TRACE("detectSQLi: " + part + "->" + key + " passed detection");
  return false;
}

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
bool detectSQLiOnParams(QueryParams params, bool include, std::vector<std::string> keys,
                        std::string part) {
  LOG_TRACE("detect SQL injection on " + part);
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
    if (detectSQLi(param->second, key, part)) {
      return true;
    }
  }
  return false;
}

class ExampleRootContext : public RootContext {
public:
  explicit ExampleRootContext(uint32_t id, StringView root_id) : RootContext(id, root_id) {}

  bool onConfigure(size_t config_size) override;
  bool onStart(size_t) override;
  Config getConfig() { return config; }

private:
  struct Config config;
};

class ExampleContext : public Context {
public:
  explicit ExampleContext(uint32_t id, RootContext* root) : Context(id, root) {}

  void onCreate() override;
  FilterHeadersStatus onRequestHeaders(uint32_t headers, bool end_of_stream) override;
  FilterDataStatus onRequestBody(size_t body_buffer_length, bool end_of_stream) override;
  FilterHeadersStatus onResponseHeaders(uint32_t headers, bool end_of_stream) override;
  void onDone() override;
  void onLog() override;
  void onDelete() override;

private:
  std::string content_type;
  struct Config config;
};
static RegisterContextFactory register_ExampleContext(CONTEXT_FACTORY(ExampleContext),
                                                      ROOT_FACTORY(ExampleRootContext),
                                                      "my_root_id");

bool ExampleRootContext::onStart(size_t) {
  LOG_TRACE("onStart");
  return true;
}

bool ExampleRootContext::onConfigure(size_t config_size) {
  if (config_size == 0) {
    return true;
  }

  // read configuration string from buffer
  auto configuration_data = getBufferBytes(WasmBufferType::PluginConfiguration, 0, config_size);
  std::string configuration = configuration_data->toString();

  // parse configuration string into Config
  std::string trace;
  if (!parseConfig(configuration, &config, &trace)) {
    LOG_ERROR("onConfigure: " + trace);
    return false;
  }
  LOG_TRACE("onConfigure: " + trace);
  return true;
}

void ExampleContext::onCreate() {
  LOG_WARN(std::string("onCreate " + std::to_string(id())));

  // get config from root
  ExampleRootContext* root = dynamic_cast<ExampleRootContext*>(this->root());
  config = root->getConfig();
  LOG_TRACE("onCreate: config loaded from root context ->" + config.to_string());
}

FilterHeadersStatus ExampleContext::onRequestHeaders(uint32_t, bool) {
  // get header pairs
  LOG_DEBUG(std::string("onRequestHeaders ") + std::to_string(id()));
  auto result = getRequestHeaderPairs();
  auto pairs = result->pairs();

  // log all headers
  QueryParams headers;
  LOG_INFO(std::string("headers: ") + std::to_string(pairs.size()));
  for (auto& p : pairs) {
    LOG_INFO(std::string(p.first) + std::string(" -> ") + std::string(p.second));
    headers.emplace(p.first, p.second);
  }
  LOG_TRACE("all headers printed");

  // detect SQL injection in headers
  if (detectSQLiOnParams(headers, config.header_include, config.headers, "Header")) {
      return FilterHeadersStatus::StopIteration;
  }

  // detect SQL injection in cookies
  std::string cookie_str = getRequestHeader("Cookie")->toString();
  QueryParams cookies = parseCookie(cookie_str);
  LOG_TRACE("Cookies parsed: " + toString(cookies));
  if (detectSQLiOnParams(cookies, config.cookie_include, config.cookies, "Cookie")) {
    return FilterHeadersStatus::StopIteration;
  }

  // detect SQL injection in path
  std::string path = getRequestHeader(":path")->toString();
  QueryParams path_params = parsePath(path);
  LOG_TRACE("Path parsed: " + toString(path_params));
  if (detectSQLiOnParams(cookies, false, {}, "Path")) {
    return FilterHeadersStatus::StopIteration;
  }

  // record body content type to context
  content_type = getRequestHeader("content-type")->toString();

  return FilterHeadersStatus::Continue;
}

FilterDataStatus ExampleContext::onRequestBody(size_t body_buffer_length, bool end_of_stream) {
  auto body = getBufferBytes(WasmBufferType::HttpRequestBody, 0, body_buffer_length);
  auto body_str = std::string(body->view());
  LOG_ERROR(std::string("onRequestBody ") + body_str);

  if (content_type.compare("application/x-www-form-urlencoded") != 0) {
    return FilterDataStatus::Continue;
  }

  // detect SQL injection in query parameters
  auto query_params = parseBody(body_str);
  LOG_TRACE("Query params parsed: " + toString(query_params));
  if (detectSQLiOnParams(query_params, config.param_include, config.params, "Query params")) {
      return FilterDataStatus::StopIterationNoBuffer;
  }
  return FilterDataStatus::Continue;
}

FilterHeadersStatus ExampleContext::onResponseHeaders(uint32_t, bool) {
  LOG_DEBUG(std::string("onResponseHeaders ") + std::to_string(id()));
  auto result = getResponseHeaderPairs();
  auto pairs = result->pairs();
  LOG_INFO(std::string("headers: ") + std::to_string(pairs.size()));
  for (auto& p : pairs) {
    LOG_INFO(std::string(p.first) + std::string(" -> ") + std::string(p.second));
  }
  addResponseHeader("branch", "libinjection-config");
  replaceResponseHeader("location", "envoy-wasm");
  return FilterHeadersStatus::Continue;
}


void ExampleContext::onDone() { LOG_WARN(std::string("onDone " + std::to_string(id()))); }

void ExampleContext::onLog() { LOG_WARN(std::string("onLog " + std::to_string(id()))); }

void ExampleContext::onDelete() { LOG_WARN(std::string("onDelete " + std::to_string(id()))); }
