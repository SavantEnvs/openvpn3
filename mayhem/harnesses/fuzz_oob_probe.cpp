// Out-of-band server probes (openvpn/ssl/oob_probe.hpp, ProtoContext::ProbeWrap): what a client's
// ServerProber does with a datagram from a probed server (ProbeWrap::unwrap -- tls-auth HMAC,
// tls-crypt decrypt, or plaintext -- then oob::probe_reply_find TLV parsing), and the TLV parsers
// of both directions (probe_request_find, as a server reads a SERVER_PROBE payload).
//
// Input: byte 0 bits 0-1 select the client's control-channel wrapping (plain / tls-auth / tls-crypt /
// tls-crypt-v2); bit 2 instead feeds the rest straight to both TLV finders. The rest is one datagram.
#include "fuzz_common.hpp"
#include "fuzz_proto_config.hpp"

#include <openvpn/ssl/oob_probe.hpp>

using namespace openvpn;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static InitProcess::Init init;
    if (size < 1)
        return 0;
    const unsigned sel = data[0];
    data++;
    size--;

    Time now = Time::from_seconds_since_epoch(1767225600);
    StrongRandomAPI::Ptr rng(new fuzz::FixedRand());
    Frame::Ptr frame = frame_init_simple(2048);
    SessionStats::Ptr stats(new fuzz::FuzzStats);
    try
    {
        BufferAllocated buf;
        frame->prepare(Frame::READ_LINK_UDP, buf);
        if (size > buf.remaining())
            size = buf.remaining();
        buf.write(data, size);
        if (sel & 4)
        {
            Buffer b1(buf);
            const auto req = oob::probe_request_find(b1);
            Buffer b2(buf);
            const auto rep = oob::probe_reply_find(b2);
            (void)req.has_value();
            (void)rep.has_value();
            return 0;
        }
        ProtoContext::ProtoConfig::Ptr cfg = fuzz::make_config(false, sel & 3, now, frame, rng, stats);
        ProtoContext::ProbeWrap wrap(cfg, stats);
        BufferAllocated work;
        ProtoSessionID src;
        PacketIDControl pid;
        if (wrap.unwrap(buf, work, src, pid) == ProtoContext::UnwrapStatus::OK)
        {
            const auto reply = oob::probe_reply_find(buf);
            (void)reply.has_value();
        }
    }
    catch (const std::exception &)
    {
    }
    return 0;
}
