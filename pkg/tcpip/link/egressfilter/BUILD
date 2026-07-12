load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "egressfilter",
    srcs = [
        "dns.go",
        "egressfilter.go",
        "filter.go",
        "rst.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/buffer",
        "//pkg/egressallowlist",
        "//pkg/log",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/header/parse",
        "//pkg/tcpip/link/nested",
        "//pkg/tcpip/stack",
        "@org_golang_x_net//dns/dnsmessage:go_default_library",
    ],
)

go_test(
    name = "egressfilter_test",
    size = "small",
    srcs = [
        "dns_test.go",
        "egressfilter_test.go",
        "rst_test.go",
    ],
    library = ":egressfilter",
    deps = [
        "//pkg/buffer",
        "//pkg/refs",
        "//pkg/tcpip",
        "//pkg/tcpip/faketime",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/stack",
        "@org_golang_x_net//dns/dnsmessage:go_default_library",
    ],
)
