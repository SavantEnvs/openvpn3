// Stateless server handshake (openvpn/ssl/psid_cookie_impl.hpp): PsidCookieImpl::intercept() sees
// every datagram a UDP server receives from a not-yet-known client address, before any session
// exists: the client's initial HARD_RESET (tls-auth HMAC check, tls-crypt-v2 WKc unwrap) and the
// third packet that returns the cookie (ACK parsing, tls-crypt-v2 CONTROL_WKC_V1).
//
// Input: same framing as fuzz_proto (its server-side seeds replay here): byte 0 bits 0-1 select
// tls-auth (1), tls-crypt-v2 (3) or both (0, 2: tls-crypt-v2 server that also holds a tls-auth
// key); the rest is datagrams, each a 2-byte big-endian length then the bytes.
#include "fuzz_common.hpp"
#include "fuzz_proto_config.hpp"

#include <openvpn/server/servproto.hpp>
#include <openvpn/ssl/psid_cookie_impl.hpp>

using namespace openvpn;

namespace {
class FixedAddr : public PsidCookieAddrInfoBase
{
  public:
    const unsigned char *get_abstract_cli_addrport(size_t &slab_size) const override
    {
        static const unsigned char addr[18] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 198, 51, 100, 7, 0x04, 0xaa};
        slab_size = sizeof(addr);
        return addr;
    }
    const void *get_impl_info() const override
    {
        return nullptr;
    }
};

class NullTransport : public PsidCookieTransportBase
{
  public:
    bool psid_cookie_send_const(Buffer &send_buf, const PsidCookieAddrInfoBase &pcaib) override
    {
        return true;
    }
};
} // namespace

// One server configuration per `sel`, built on first use and reused for the whole process, as a
// real server builds its config once for its lifetime. This is required, not an optimisation:
// upstream psid_cookie_impl.hpp caches values from the config in function-local statics the first
// time each function runs (`static const Frame &frame = *pcfg_.frame;` and the
// `static const size_t hmac_size` reads of the tls-auth / tls-crypt contexts). A config rebuilt per
// input would leave those statics pointing at the first input's Frame. With one long-lived config
// per sel they always refer to live objects, and every value they cache (2048-byte frame, SHA256
// HMAC sizes) is the same for all four sels, so no input's result depends on an earlier one.
// The per-input state is reset at the start of each input: the clock (`now`, which the config
// points at), the RNG seed, and a fresh PsidCookieImpl (its HMAC contexts).
namespace {
struct ServerSetup
{
    Frame::Ptr frame;
    fuzz::FixedRand::Ptr rng;
    ProtoContext::ProtoConfig::Ptr pcfg;
    ServerProto::Factory::Ptr spf;
};

Time g_now;
constexpr Time::base_type kStartSeconds = 1767225600;

ServerSetup &server_setup(unsigned sel, openvpn_io::io_context &io_context)
{
    static ServerSetup setups[4];
    ServerSetup &s = setups[sel];
    if (s.spf)
        return s;
    s.frame = frame_init_simple(2048);
    s.rng.reset(new fuzz::FixedRand());
    SessionStats::Ptr stats(new fuzz::FuzzStats);
    s.pcfg = fuzz::make_config(true, sel == 1 ? 1 : 3, g_now, s.frame, s.rng, stats);
    if (sel == 0 || sel == 2)
    {
        s.pcfg->tls_auth_factory.reset(new CryptoOvpnHMACFactory<SSLLib::CryptoAPI>());
        s.pcfg->tls_auth_key.parse(fuzzkeys::tls_auth_key);
        s.pcfg->set_tls_auth_digest(CryptoAlgs::lookup("SHA256"));
        s.pcfg->key_direction = 1;
    }
    s.spf.reset(new ServerProto::Factory(io_context, *s.pcfg));
    s.spf->proto_context_config = s.pcfg;
    return s;
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static InitProcess::Init init;
    static const bool setup = (PsidCookieImpl::pre_threading_setup(), true);
    (void)setup;
    static openvpn_io::io_context io_context(1);
    if (size < 1)
        return 0;
    const unsigned sel = data[0] & 3;
    data++;
    size--;

    g_now = Time::from_seconds_since_epoch(kStartSeconds);
    try
    {
        ServerSetup &s = server_setup(sel, io_context);
        s.rng->reseed();
        Frame::Ptr frame = s.frame;
        PsidCookieImpl pci(s.spf.get());
        pci.provide_psid_cookie_transport(PsidCookieTransportBase::Ptr(new NullTransport()));
        const FixedAddr addr;

        size_t off = 0;
        while (off + 2 <= size)
        {
            size_t len = (static_cast<size_t>(data[off]) << 8) | data[off + 1];
            off += 2;
            len = std::min(len, size - off);
            BufferAllocated buf;
            frame->prepare(Frame::READ_LINK_UDP, buf);
            if (len > buf.remaining())
                len = buf.remaining();
            buf.write(data + off, len);
            off += len;
            try
            {
                const PsidCookie::Intercept r = pci.intercept(buf, addr);
                if (r == PsidCookie::Intercept::HANDLE_2ND)
                    (void)pci.get_cookie_psid();
            }
            catch (const std::exception &)
            {
            }
            g_now += Time::Duration::milliseconds(100);
        }
    }
    catch (const std::exception &)
    {
    }
    return 0;
}
