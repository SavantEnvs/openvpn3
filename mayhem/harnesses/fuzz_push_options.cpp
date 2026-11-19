// Server-pushed options: what the client does with PUSH_REPLY messages (cliproto.hpp
// recv_push_reply): OptionList::parse_from_csv (pushlex), PushedOptionsFilter,
// OptionListContinuation (push-continuation), then TunProp::configure_builder (routes,
// ifconfig, dhcp-option, redirect-gateway ...) into a TunBuilderCapture, and DnsOptionsParser.
// Input: one PUSH_REPLY payload per line ("PUSH_REPLY," prefix optional).
#include "fuzz_common.hpp"
#include <openvpn/common/options.hpp>
#include <openvpn/client/cliconstants.hpp>
#include <openvpn/client/optfilt.hpp>
#include <openvpn/client/dns.hpp>
#include <openvpn/options/continuation.hpp>
#include <openvpn/tun/builder/capture.hpp>
#include <openvpn/tun/client/tunprop.hpp>

using namespace openvpn;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const std::string in(reinterpret_cast<const char *>(data), size);
    // The client's local profile only contributes the pull-filter rules here.
    static const OptionList local = OptionList::parse_from_config_static(
        "client\npull-filter ignore \"route 10.9.\"\npull-filter reject \"echo bad\"\n", nullptr);
    try
    {
        PushedOptionsFilter filter(local);
        OptionList::Limits limit("server-pushed options data too large",
                                 ProfileParseLimits::MAX_PUSH_SIZE,
                                 ProfileParseLimits::OPT_OVERHEAD,
                                 ProfileParseLimits::TERM_OVERHEAD,
                                 0,
                                 ProfileParseLimits::MAX_DIRECTIVE_SIZE);
        OptionListContinuation received;
        size_t pos = 0;
        while (pos <= in.size() && !received.complete())
        {
            size_t nl = in.find('\n', pos);
            if (nl == std::string::npos)
                nl = in.size();
            std::string msg = in.substr(pos, nl - pos);
            pos = nl + 1;
            if (msg.starts_with("PUSH_REPLY,"))
                msg = msg.substr(11);
            OptionList opts = OptionList::parse_from_csv_static(msg, &limit);
            received.add(opts, &filter);
        }
        if (!received.complete())
            return 0;
        received.finalize(PushOptionsMerger::Ptr());

        TunBuilderCapture::Ptr tb(new TunBuilderCapture());
        TunProp::State::Ptr state(new TunProp::State());
        TunProp::Config config;
        config.mtu = 1500;
        config.mtu_max = 65535;
        const IP::Addr server = IP::Addr::from_string("192.0.2.1");
        TunProp::configure_builder(tb.get(), state.get(), nullptr, server, config, received, nullptr, true);
        (void)tb->to_string();
        DnsOptionsParser dns(received, true);
        (void)dns.to_string();
    }
    catch (const std::exception &)
    {
    }
    return 0;
}
