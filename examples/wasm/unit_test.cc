#include "gtest/gtest.h"

#include "config.h"

TEST(ConfigTest, DefaultConfig) {
  Config config;
  EXPECT_EQ(config.content_type, URLENCODED);
}
