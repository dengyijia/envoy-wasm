#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "examples/wasm/utility/http_parser.h"

using ::testing::Eq;
using ::testing::UnorderedElementsAreArray;
using ::testing::IsEmpty;

MATCHER_P(ParamsEq, expected_params, "Params are not equal") {
  if (expected_params.size() != arg.size()) {
    return false;
  }
  for (auto param : expected_params) {
    auto match = arg.find(param.first);
    if (match == arg.end() || match->second != param.second) {
      return false;
    }
  }
  return true;
}

TEST(HttpParserTest, PercentDecodingTest) {
  ASSERT_EQ(percentDecode(""), "");
  ASSERT_EQ(percentDecode("not-encoded"), "not-encoded");
}

TEST(HttpParserTest, ParseCookieTest) {
  QueryParams params0 = parseCookie("");
  QueryParams expected0 ({});
  ASSERT_THAT(params0, ParamsEq(expected0));
}

TEST(HttpParserTest, ParseBodyTest) {

}

TEST(HttpParserTest, ParsePathTest) {

}
