#include "examples/wasm/config.h"

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

std::string Config::to_string() {
  std::string param_str = "\nquery param " + config_field_to_string(param_include, params);
  std::string header_str = "\nheaders " + config_field_to_string(header_include, headers);
  std::string cookie_str = "\ncookies " + config_field_to_string(cookie_include, cookies);
  return "config: " + content_type + param_str + header_str + cookie_str;
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
bool validate_config_field(json field, bool* include, std::vector<std::string>* params,
                           std::string* trace) {
   if (field.is_null()) {
     return true;
   }
   if (!field["include"].is_null() && !field["exclude"].is_null()) {
     *trace = "include and exclude cannot both be present";
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

bool parseConfig(std::string configuration, Config* config, std::string* trace) {
  // parse configuration string as json
  json j = json::parse(configuration, nullptr, false);
  if (j.is_discarded()) {
    *trace = "JSON parse error in configuration";
    return false;
  }

  // validate query param configuration
  auto query_param = j["query_param"];
  if (!query_param.is_null()) {
    if (query_param["Content-Type"].is_null()) {
      *trace = "missing Content-Type field under query_param";
      return false;
    }
    std::string content_type = query_param["Content-Type"].get<std::string>();
    if (content_type.compare(URLENCODED) != 0) {
      *trace = ("invalid content type, only application/x-www-form-urlencoded is supported\n");
      return false;
    }
    if (!validate_config_field(query_param, &config->param_include, &config->params, trace)) {
      return false;
    }
  }
  // validate cookie configuration
  if (!validate_config_field(j["cookie"], &config->cookie_include, &config->cookies, trace)) {
    return false;
  }
  // validate header configuration
  if (!validate_config_field(j["header"], &config->header_include, &config->headers, trace)) {
    return false;
  }
  *trace = "onConfigure: config parsed into context ->" + config->to_string();
  return true;
}


