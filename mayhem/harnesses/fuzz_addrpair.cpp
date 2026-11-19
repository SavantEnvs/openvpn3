// IP address / netmask / route string parsers (route, ifconfig and push options carry these).
// Reaches IP::AddrMaskPair::from_string (upstream fix c33d2c44), IP::Route, IP::Addr, HostPort.
#include "fuzz_common.hpp"
#include <openvpn/addr/addrpair.hpp>
#include <openvpn/addr/route.hpp>
#include <openvpn/addr/ip.hpp>
#include <openvpn/common/hostport.hpp>

using namespace openvpn;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const std::string s(reinterpret_cast<const char *>(data), size);
    try
    {
        IP::AddrMaskPair p = IP::AddrMaskPair::from_string(s, "fuzz");
        (void)p.to_string(true);
    }
    catch (const std::exception &)
    {
    }
    try
    {
        IP::Route r = IP::Route::from_string(s, "fuzz");
        (void)r.to_string();
        (void)r.is_canonical();
    }
    catch (const std::exception &)
    {
    }
    try
    {
        IP::Addr a = IP::Addr::from_string(s, "fuzz");
        (void)a.to_string();
    }
    catch (const std::exception &)
    {
    }
    try
    {
        std::string host, port;
        if (HostPort::split_host_port(s, host, port, "1194", false))
            (void)HostPort::is_valid_host(host);
    }
    catch (const std::exception &)
    {
    }
    return 0;
}
