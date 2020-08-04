#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "config.h"
#include "query_param.h"
#include "sqli.h"

using ::testing::Eq;
using ::testing::ElementsAre;

// Check that invalid json formatting will be handled
TEST(ConfigTest, InvalidFormattingConfig) {
  std::string trace;
  Config config;
  bool result = parseConfig("invalid json format {}", &config, &trace);
  ASSERT_EQ(result, false);
}

// Check that empty config string corresponds to default setting
TEST(ConfigTest, EmptyConfig) {
  std::string trace;
  Config config;
  parseConfig("", &config, &trace);

  ASSERT_EQ(config.content_type, URLENCODED);

  ASSERT_EQ(config.param_include, false);
  ASSERT_EQ(config.params.size(), 0);

  ASSERT_EQ(config.header_include, true);
  ASSERT_THAT(config.headers, ElementsAre("referer", "user-agent"));

  ASSERT_EQ(config.cookie_include, false);
  ASSERT_EQ(config.cookies.size(), 0);
}

// Check that query param inputs are parsed correctly
TEST(ConfigTest, QueryParams) {
  std::string trace;
  bool result;

  // failure: missing content-type in config string
  Config config_none;
  std::string param_none = R"(
  {
    "query_param": {}
  }
  )";
  result = parseConfig(param_none, &config_none, &trace);
  ASSERT_EQ(result, false);

  // failure: content-type not supported
  Config config_unsupported;
  std::string param_unsupported = R"(
  {
    "query_param": {
       "content-type": "unsupported-type"
    }
  }
  )";
  result = parseConfig(param_unsupported, &config_unsupported, &trace);
  ASSERT_EQ(result, false);

  // success: default config when no include/exclude is provided
  Config config_default;
  std::string param_default = R"(
  {
    "query_param": {
      "content-type": "application/x-www-form-urlencoded"
    }
  }
  )";
  result = parseConfig(param_default, &config_default, &trace);
  ASSERT_EQ(result, true);
  ASSERT_EQ(config_default.param_include, false);
  ASSERT_EQ(config_default.params.size(), 0);

  // success: include is provided
  Config config_include;
  std::string param_include = R"(
  {
    "query_param": {
      "content-type": "application/x-www-form-urlencoded",
      "include": ["foo", "bar"]
    }
  }
  )";
  result = parseConfig(param_include, &config_include, &trace);
  ASSERT_EQ(result, true);
  ASSERT_EQ(config_include.param_include, true);
  ASSERT_THAT(config_include.params, ElementsAre("foo", "bar"));

  // success: exclude is provided
  Config config_exclude;
  std::string param_exclude = R"(
  {
    "query_param": {
      "content-type": "application/x-www-form-urlencoded",
      "exclude": ["foo", "bar"]
    }
  }
  )";
  result = parseConfig(param_exclude, &config_exclude, &trace);
  ASSERT_EQ(result, true);
  ASSERT_EQ(config_exclude.param_include, false);
  ASSERT_THAT(config_exclude.params, ElementsAre("foo", "bar"));

  // failure: both include and exclude are provided
  Config config_both;
  std::string param_both = R"(
  {
    "query_param": {
      "content-type": "application/x-www-form-urlencoded",
      "exclude": ["foo", "bar"],
      "include": [],
    }
  }
  )";
  result = parseConfig(param_both, &config_both, &trace);
  ASSERT_EQ(result, false);
}

TEST(ConfigTest, Header) {

}

TEST(ConfigTest, Cookie) {

}

TEST(QueryParamParserTest, Path) {

}

TEST(QueryParamParserTest, Body) {

}

TEST(QueryParamParserTest, Cookie) {

}

TEST(SQLiDetectionTest, Path) {

}

TEST(SQLiDetectionTest, Body) {

}

TEST(SQLiDetectionTest, Cookie) {

}

TEST(SQLiDetectionTest, Header) {

}
