load(
    "//bazel:envoy_build_system.bzl",
    "envoy_package",
)
load("//bazel/wasm:wasm.bzl", "wasm_cc_binary")

licenses(["notice"])  # Apache 2

envoy_package()

cc_library(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    deps = ["@github_nlohmann_json//:json"],
)

cc_test(
    name = "unit_test",
    srcs = ["unit_test.cc"],
    deps = [
        ":config",
        "@gtest//:gtest",
        "@gtest//:gtest_main"
    ],
)
wasm_cc_binary(
    name = "envoy_filter_http_wasm_example.wasm",
    srcs = ["envoy_filter_http_wasm_example.cc"],
    deps = [
        "@proxy_wasm_cpp_sdk//:proxy_wasm_intrinsics",
        "@libinjection//:libinjection",
        ":config",
        # "@github_nlohmann_json//:json",
    ],
    linkstatic = 1,
)
