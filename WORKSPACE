workspace(name = "envoy")

load("//bazel:api_binding.bzl", "envoy_api_binding")

envoy_api_binding()

load("//bazel:api_repositories.bzl", "envoy_api_dependencies")

envoy_api_dependencies()

load("//bazel:repositories.bzl", "envoy_dependencies")

envoy_dependencies()

load("//bazel:repositories_extra.bzl", "envoy_dependencies_extra")

envoy_dependencies_extra()

load("//bazel:dependency_imports.bzl", "envoy_dependency_imports")

envoy_dependency_imports()

load("@rules_antlr//antlr:deps.bzl", "antlr_dependencies")

antlr_dependencies(471)

new_local_repository(
    name = "libinjection",
    path = "../libinjection",
    build_file = "libinjection.BUILD",
)

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
http_archive(
    name = "github_nlohmann_json",
    urls = ["https://github.com/nlohmann/json/releases/download/v3.6.1/include.zip",],
    build_file = "//:nlohmann_json.BUILD",
)



load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
git_repository(
    name = "gtest",
    remote = "https://github.com/google/googletest",
    branch = "v1.10.x",
)
