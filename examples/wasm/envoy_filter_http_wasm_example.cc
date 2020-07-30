// NOLINT(namespace-envoy)
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>

#include "nlohmann/json.hpp"
#include "proxy_wasm_intrinsics.h"
#include "src/libinjection.h"
#include "src/libinjection_sqli.h"

using json = nlohmann::json;
using QueryParams = std::map<std::string, std::string>;

const std::string URLENCODED = "application/x-www-form-urlencoded";

/*
 * Convert a config field to string
 */
std::string config_field_to_string(bool include, std::vector<std::string> params) {
  std::string str = "include: ";
  if (!include) {
    str = "exclude: ";
  }
  for (auto const& s : params) {
    str += s + ", ";
  }
  return str;
}

/*
 * Keep track of config info
 * Three main fields: param(query param), header, cookie
 *
 * If <field>_include is true, <field>s contains the names to be included in
 * sql injection detection
 * If <filed>_include is false, <field>s contains the names to be excluded
 */
struct Config {
  std::string content_type { URLENCODED };

  bool param_include { false };
  std::vector<std::string> params {};

  bool header_include { true };
  std::vector<std::string> headers { "referer", "user-agent" };

  bool cookie_include { false };
  std::vector<std::string> cookies {};

  std::string to_string() {
    std::string param_str = "\nquery param " + config_field_to_string(param_include, params);
    std::string header_str = "\nheaders " + config_field_to_string(header_include, headers);
    std::string cookie_str = "\ncookies " + config_field_to_string(cookie_include, cookies);
    return "config: " + content_type + param_str + header_str + cookie_str;
  }
};

/*
 * Check if the string val exists in the vector vec
 */
inline bool exists(std::string val, std::vector<std::string> vec) {
  return std::find(vec.begin(), vec.end(), val) != vec.end();
}

/*
 * Validate and store a field in Config
 * Input:
 *   field: a json object to be parsed, either query param, header, or cookie
 *   include: a pointer to store the parsed result (<field_include in Config)
 *   params: a pointer to store the parsed result (<field>s in Config)
 * Output:
 *   true on success
 *   false on failure (if both 'include' and 'exclude' are present in the field)
 */
bool validate_config_field(json field, bool* include, std::vector<std::string>* params) {
   if (field.is_null()) {
     return true;
   }
   if (!field["include"].is_null() && !field["exclude"].is_null()) {
     LOG_ERROR("onConfigure: \"include\" and \"exclude\" should not be used simultaneously");
     return false;
   }
   if (!field["include"].is_null()) {
     *include = true;
     auto include_params = field["include"].get<std::vector<std::string>>();
     params->insert(params->end(), include_params.begin(), include_params.end());
   }
   if (!field["exclude"].is_null()) {
     *include = false;
     *params = field["exclude"].get<std::vector<std::string>>();
   }
   return true;
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

  // parse configuration string as json
  json j = json::parse(configuration, nullptr, false);
  if (j.is_discarded()) {
    LOG_ERROR("onConfigure: JSON parse error: " + configuration);
    return false;
  }
  LOG_TRACE("onConfigure: " + configuration + ", length: " + std::to_string(config_size));

  // validate query param configuration
  auto query_param = j["query_param"];
  if (!query_param.is_null()) {
    if (query_param["Content-Type"].is_null()) {
      LOG_ERROR("onConfigure: missing Content-Type field under query_param");
      return false;
    }
    std::string content_type = query_param["Content-Type"].get<std::string>();
    if (content_type.compare(URLENCODED) != 0) {
      LOG_ERROR("onConfigure: invalid content type (" + content_type + ")\n");
      LOG_ERROR("onConfigure: only application/x-www-form-urlencoded is supported\n");
      return false;
    }
    if (!validate_config_field(query_param, &config.param_include, &config.params)) {
      return false;
    }
  }
  // validate cookie configuration
  if (!validate_config_field(j["cookie"], &config.cookie_include, &config.cookies)) {
    return false;
  }
  // validate header configuration
  if (!validate_config_field(j["header"], &config.header_include, &config.headers)) {
    return false;
  }
  LOG_TRACE("onConfigure: config parsed into context ->" + config.to_string());
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
