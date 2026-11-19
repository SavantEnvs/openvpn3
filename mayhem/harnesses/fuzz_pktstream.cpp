// TCP transport framing: PacketStream / PacketStreamResidual reassemble length-prefixed OpenVPN
// packets from a peer's TCP byte stream (openvpn/transport/pktstream.hpp), plus the
// is_openvpn_protocol() sniffer used by port-share.
#include "fuzz_common.hpp"
// pktstream.hpp calls numeric_cast unqualified (its own tests get the using-directive from
// test_helper.hpp), so provide the same using-directive here.
#include <openvpn/common/numeric_cast.hpp>
using namespace openvpn::numeric_util;
#include <openvpn/transport/pktstream.hpp>
#include <openvpn/ssl/is_openvpn_protocol.hpp>
#include <openvpn/frame/frame.hpp>

using namespace openvpn;

template <typename PKTSTREAM>
static void run(const uint8_t *data, size_t size, const Frame::Context &fc)
{
    PKTSTREAM ps;
    size_t off = 0;
    // First byte of each chunk = chunk length (1..256), the rest is the TCP stream.
    while (off < size)
    {
        size_t n = static_cast<size_t>(data[off++]) + 1;
        n = std::min(n, size - off);
        BufferAllocated in;
        fc.prepare(in);
        in.write(data + off, n);
        off += n;
        while (!in.empty())
        {
            ps.put(in, fc);
            while (ps.ready())
            {
                BufferAllocated out;
                ps.get(out, fc);
            }
        }
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1)
        return 0;
    (void)is_openvpn_protocol(data, size);
    const uint8_t sel = data[0];
    data++;
    size--;
    const Frame::Context fc(256, 512, 256, 0, sizeof(size_t), (sel & 4) ? BufAllocFlags::GROW : BufAllocFlags::NO_FLAGS);
    try
    {
        switch (sel & 3)
        {
        case 0:
            run<PacketStream<std::uint16_t>>(data, size, fc);
            break;
        case 1:
            run<PacketStream<std::uint32_t>>(data, size, fc);
            break;
        case 2:
            run<PacketStreamResidual<std::uint16_t>>(data, size, fc);
            break;
        default:
            run<PacketStreamResidual<std::uint32_t>>(data, size, fc);
            break;
        }
    }
    catch (const std::exception &)
    {
    }
    return 0;
}
