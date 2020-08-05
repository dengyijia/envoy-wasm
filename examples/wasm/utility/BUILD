load(
    "//bazel:envoy_build_system.bzl",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

cc_library(
    name = "config",
    srcs = ["config.cc", "common.h"],
    hdrs = ["config.h"],
    deps = ["@github_nlohmann_json//:json"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "query_parser",
    srcs = ["query_parser.cc", "common.h"],
    hdrs = ["query_parser.h"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "sqli",
    srcs = ["sqli.cc", "common.h"],
    hdrs = ["sqli.h"],
    deps = [
        ":query_parser",
        "@libinjection//:libinjection",
    ],
    visibility = ["//visibility:public"],
)


