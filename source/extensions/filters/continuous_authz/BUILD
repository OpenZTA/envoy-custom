load("@envoy//bazel:envoy_build_system.bzl", "envoy_cc_library")

package(default_visibility = ["//visibility:public"])
licenses(["notice"])

envoy_cc_library(
    name = "continuous_authz",
    repository = "@envoy",
    srcs = ["config.cc", "http.cc", "network.cc", "recheck.cc"],
    hdrs = ["http.h", "network.h", "recheck.h"],
    alwayslink = True,
    deps = [
        "//api/extensions/filters/continuous_authz:pkg_cc_proto",
        "@envoy//envoy/api:api_interface",
        "@envoy//envoy/event:dispatcher_interface",
        "@envoy//envoy/grpc:async_client_manager_interface",
        "@envoy//envoy/network:connection_interface",
        "@envoy//envoy/router:router_interface",
        "@envoy//envoy/ssl:connection_interface",
        "@envoy//envoy/registry",
        "@envoy//envoy/stats:stats_interface",
        "@envoy//envoy/common:exception_lib",
        "@envoy//source/common/config:utility_lib",
        "@envoy//source/common/http:header_map_lib",
        "@envoy//source/common/protobuf:utility_lib",
        "@envoy//source/common/stream_info:bool_accessor_lib",
        "@envoy//source/common/tracing:tracer_lib",
        "@envoy//source/extensions/filters/common/ext_authz:ext_authz_grpc_lib",
        "@envoy//source/extensions/filters/common/ext_authz:ext_authz_http_lib",
        "@envoy//source/extensions/filters/common/ext_authz:check_request_utils_lib",
        "@envoy//source/extensions/filters/http/common:factory_base_lib",
        "@envoy//source/extensions/filters/http/ext_authz",
        "@envoy//source/extensions/filters/network/common:factory_base_lib",
        "@envoy//source/extensions/filters/network/ext_authz",
    ],
)
