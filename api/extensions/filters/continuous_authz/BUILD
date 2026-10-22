load("@envoy_api//bazel:api_build_system.bzl", "api_proto_package")

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

api_proto_package(
    deps = [
        "@envoy_api//envoy/extensions/filters/http/ext_authz/v3:pkg",
        "@envoy_api//envoy/extensions/filters/network/ext_authz/v3:pkg",
    ],
)
