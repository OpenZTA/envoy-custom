load("@envoy//bazel:envoy_build_system.bzl", "envoy_cc_test")

licenses(["notice"])

envoy_cc_test(
    name = "recheck_test",
    srcs = ["recheck_test.cc", "network_test.cc", "http_test.cc"],
    repository = "@envoy",
    deps = [
        "//source/extensions/filters/continuous_authz:continuous_authz",
        "@envoy//envoy/stream_info:bool_accessor_interface",
        "@envoy//source/common/network:address_lib",
        "@envoy//source/common/stats:isolated_store_lib",
        "@envoy//test/extensions/filters/common/ext_authz:ext_authz_mocks",
        "@envoy//test/mocks/event:event_mocks",
        "@envoy//test/mocks/http:http_mocks",
        "@envoy//test/mocks/network:network_mocks",
        "@envoy//test/mocks/server:server_factory_context_mocks",
        "@envoy//test/mocks/ssl:ssl_mocks",
        "@envoy//test/mocks:common_lib",
        "@envoy//test/mocks/stream_info:stream_info_mocks",
        "@envoy//test/test_common:utility_lib",
    ],
)
