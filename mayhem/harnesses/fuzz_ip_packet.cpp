// IP packets carried in the tunnel: MSSFix::mssfix (applied by proto.hpp to packets decrypted
// from the peer: IPv4/IPv6 header and TCP option walk), Ptb::generate_icmp_ptb (ICMP "packet too
// big" built from an oversize packet, cliproto.hpp) and DHCPCapture::mod_reply (DHCP option walk
// over replies from the server, Windows tun client).
// Input: 2 bytes MSS / next-hop MTU (big-endian), then the packet.
#include "fuzz_common.hpp"
// mssfix.hpp uses numeric_util unqualified (upstream gets the using-directive from proto.hpp).
#include <openvpn/common/numeric_cast.hpp>
using namespace openvpn::numeric_util;
#include <openvpn/transport/mssfix.hpp>
#include <openvpn/ip/ptb.hpp>
#include <openvpn/tun/builder/capture.hpp>
#include <openvpn/tun/client/dhcp_capture.hpp>

using namespace openvpn;

static void load(BufferAllocated &buf, const uint8_t *data, size_t size)
{
    // headroom like a received data-channel packet, so prepending headers is possible
    buf.reset(128, size + 256, BufAllocFlags::NO_FLAGS);
    buf.write(data, size);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2)
        return 0;
    const std::uint16_t mss = static_cast<std::uint16_t>((data[0] << 8) | data[1]);
    data += 2;
    size -= 2;
    try
    {
        BufferAllocated buf;
        load(buf, data, size);
        MSSFix::mssfix(buf, mss);
    }
    catch (const std::exception &)
    {
    }
    try
    {
        BufferAllocated buf;
        load(buf, data, size);
        if (!buf.empty())
            Ptb::generate_icmp_ptb(buf, mss);
    }
    catch (const std::exception &)
    {
    }
    try
    {
        TunBuilderCapture::Ptr tbc(new TunBuilderCapture());
        tbc->tun_builder_add_address("10.8.0.2", 24, "10.8.0.1", false, false);
        DHCPCapture dc(tbc);
        BufferAllocated buf;
        load(buf, data, size);
        (void)dc.mod_reply(buf);
    }
    catch (const std::exception &)
    {
    }
    return 0;
}
