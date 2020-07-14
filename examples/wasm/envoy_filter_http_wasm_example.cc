// NOLINT(namespace-envoy)
#include <string>
#include <unordered_map>
// #include <google/protobuf/util/json_util.h>

#include "proxy_wasm_intrinsics.h"
#include "src/libinjection.h"
#include "src/libinjection_sqli.h"

class ExampleRootContext : public RootContext {
public:
  explicit ExampleRootContext(uint32_t id, StringView root_id) : RootContext(id, root_id) {}

  bool onConfigure(size_t config_size) override;
  bool onStart(size_t) override;
};

class ExampleContext : public Context {
public:
  explicit ExampleContext(uint32_t id, RootContext* root) : Context(id, root) {}

  void onCreate() override;
  //void onConfigure(size_t config_size) override;
  FilterHeadersStatus onRequestHeaders(uint32_t headers, bool end_of_stream) override;
  FilterDataStatus onRequestBody(size_t body_buffer_length, bool end_of_stream) override;
  FilterHeadersStatus onResponseHeaders(uint32_t headers, bool end_of_stream) override;
  void onDone() override;
  void onLog() override;
  void onDelete() override;

//private:
//  Config config;
};
static RegisterContextFactory register_ExampleContext(CONTEXT_FACTORY(ExampleContext),
                                                      ROOT_FACTORY(ExampleRootContext),
                                                      "my_root_id");

bool ExampleRootContext::onStart(size_t) {
  LOG_TRACE("onStart");
  return true;
}

void ExampleContext::onCreate() { LOG_WARN(std::string("onCreate " + std::to_string(id()))); }

bool ExampleRootContext::onConfigure(size_t config_size) {
  // read configuration string from buffer
  std::string configuration = "EMPTY CONFIG";
  if (config_size > 0) {
    auto configuration_data = getBufferBytes(WasmBufferType::PluginConfiguration, 0, config_size);
    configuration = configuration_data->toString();
  }

  // parse configuration JSON string
 // JsonParseOptions json_options;
  //json_options.ignore_unknown_fields = true;
  //Status status = JsonStringToMessage(configuration, &config, json_options);
  //if (status != Status::OK) {
  //  LOG_WARN("Cannot parse configuration JSON string " + configuration + ", " + status.message().ToString());
  //  return false;
  //}

  LOG_TRACE("onConfigure: " + configuration + ", length: " + std::to_string(config_size));
  return true;
}

FilterHeadersStatus ExampleContext::onRequestHeaders(uint32_t, bool) {
  LOG_DEBUG(std::string("onRequestHeaders ") + std::to_string(id()));
  auto result = getRequestHeaderPairs();
  auto pairs = result->pairs();
  LOG_INFO(std::string("headers: ") + std::to_string(pairs.size()));
  for (auto& p : pairs) {
    LOG_INFO(std::string(p.first) + std::string(" -> ") + std::string(p.second));
  }
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
  addResponseHeader("branch", "libinjection");
  replaceResponseHeader("location", "envoy-wasm");
  return FilterHeadersStatus::Continue;
}

FilterDataStatus ExampleContext::onRequestBody(size_t body_buffer_length, bool end_of_stream) {
  auto body = getBufferBytes(WasmBufferType::HttpRequestBody, 0, body_buffer_length);
  auto body_str = std::string(body->view());
  LOG_ERROR(std::string("onRequestBody ") + body_str);

  struct libinjection_sqli_state state;
  int issqli;

  const char* input = const_cast<char*>(body_str.c_str());
  libinjection_sqli_init(&state, input, body_buffer_length, FLAG_NONE);
  issqli = libinjection_is_sqli(&state);
  if (issqli) {
      sendLocalResponse(403, "SQL injection detected", std::string("fingerprint: ") + std::string(state.fingerprint), {});
  } else {
      sendLocalResponse(200, "The SQL is fine", body_str, {});
  }
  return FilterDataStatus::StopIterationNoBuffer;
}

void ExampleContext::onDone() { LOG_WARN(std::string("onDone " + std::to_string(id()))); }

void ExampleContext::onLog() { LOG_WARN(std::string("onLog " + std::to_string(id()))); }

void ExampleContext::onDelete() { LOG_WARN(std::string("onDelete " + std::to_string(id()))); }
