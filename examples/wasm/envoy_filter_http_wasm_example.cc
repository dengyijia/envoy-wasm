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
  std::string content_type { "application/x-www-form-urlencoded" };

  bool param_include { false };
  std::vector<std::string> params {};

  bool header_include { true };
  std::vector<std::string> headers { "Referrer", "User-Agent" };

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
 * Detect SQL injection with libinjection method
 */
bool detectSQLi(std::string input) {
  struct libinjection_sqli_state state;
  char* input_char_str = const_cast<char*>(input.c_str());
  libinjection_sqli_init(&state, input_char_str, input.length(), FLAG_NONE);

  int issqli = libinjection_is_sqli(&state);
  if (issqli) {
    sendLocalResponse(403, "SQL injection detected",
                     std::string("fingerprint: ") + std::string(state.fingerprint), {});
    return true;
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
    if (content_type.compare("application/x-www-form-urlencoded") != 0) {
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
}

FilterHeadersStatus ExampleContext::onRequestHeaders(uint32_t, bool) {
  // get header pairs
  LOG_DEBUG(std::string("onRequestHeaders ") + std::to_string(id()));
  auto result = getRequestHeaderPairs();
  auto pairs = result->pairs();

  // log all headers
  LOG_INFO(std::string("headers: ") + std::to_string(pairs.size()));
  for (auto& p : pairs) {
    LOG_INFO(std::string(p.first) + std::string(" -> ") + std::string(p.second));
  }

  // record body content type to context
  content_type = getRequestHeader("Content-Type")->toString();

  // find configured headers to detect sql injection
  std::vector<std::string> headers;
  if (config.header_include) {
    headers = config.headers;
  } else {
    for (auto& p : pairs) {
      std::string header = std::string(p.first);
      if (exists(header, config.headers)) {
        headers.push_back(header);
      }
    }
  }

  // detect sql injection in configured headers
  for (auto header : headers) {
    std::string value = getRequestHeader(header)->toString();
    if (detectSQLi(value)) {
      return FilterHeadersStatus::StopIteration;
    }
    LOG_TRACE("onRequestHeaders: header " + header + "passed detection");
  }

  // TODO  find configured cookies to detect sql injection
  // TODO  detect sql injection in configured cookies
  // TODO  detect sql injection in path
  return FilterHeadersStatus::Continue;
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

FilterDataStatus ExampleContext::onRequestBody(size_t body_buffer_length, bool end_of_stream) {
  auto body = getBufferBytes(WasmBufferType::HttpRequestBody, 0, body_buffer_length);
  auto body_str = std::string(body->view());
  LOG_ERROR(std::string("onRequestBody ") + body_str);

  if (content_type.compare("application/x-www-form-urlencoded") != 0) {
    return FilterDataStatus::Continue;
  }

  // TODO parse body string into param value pairs
  // TODO find configured params to detect sql injection
  // TODO detect sql injection in configured params

  if (detectSQLi(body_str)) {
      return FilterDataStatus::StopIterationNoBuffer;
  }
  return FilterDataStatus::Continue;
}

void ExampleContext::onDone() { LOG_WARN(std::string("onDone " + std::to_string(id()))); }

void ExampleContext::onLog() { LOG_WARN(std::string("onLog " + std::to_string(id()))); }

void ExampleContext::onDelete() { LOG_WARN(std::string("onDelete " + std::to_string(id()))); }
