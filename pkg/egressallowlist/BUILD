load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "egressallowlist",
    srcs = [
        "ips.go",
        "match.go",
    ],
    visibility = ["//visibility:public"],
)

go_test(
    name = "egressallowlist_test",
    size = "small",
    srcs = ["egressallowlist_test.go"],
    library = ":egressallowlist",
)
