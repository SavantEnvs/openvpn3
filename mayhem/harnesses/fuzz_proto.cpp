// OpenVPN control/data channel receive path (openvpn/ssl/proto.hpp), as a server receiving packets
// from an untrusted client or a client receiving packets from an untrusted server: packet_type(),
// control_net_recv() (tls-auth HMAC / tls-crypt / tls-crypt-v2 WKc unwrap, reliability + ACK layer,
// packet-id replay check, TLS handshake via OpenSSL, key-method-2 parsing) and data_decrypt().
//
// Input: byte 0 selects the configuration (bits 0-1: none / tls-auth / tls-crypt / tls-crypt-v2,
// bit 2: client instead of server); the rest is a sequence of datagrams, each a 2-byte big-endian
// length followed by that many bytes. A fresh ProtoContext is built for every input.
#include "fuzz_common.hpp"
#include "fuzz_proto_config.hpp"

#include <deque>

using namespace openvpn;
using fuzz::FuzzStats;
using fuzz::make_config;

namespace {

class Peer : public ProtoContextCallbackInterface
{
  public:
    Peer(const ProtoContext::ProtoConfig::Ptr &cfg, const SessionStats::Ptr &stats)
        : proto(this, cfg, stats)
    {
    }

    void control_net_send(const Buffer &net_buf) override
    {
        ++n_sent;
        if (record)
            record->push_back(std::string(reinterpret_cast<const char *>(net_buf.c_data()), net_buf.size()));
    }
    void control_recv(BufferPtr &&app_bp) override
    {
        // The application layer above ProtoContext sees these (PUSH_REQUEST, AUTH ...).
        if (app_bp)
            received.push_back(std::string(reinterpret_cast<const char *>(app_bp->c_data()), app_bp->size()));
    }
    void client_auth(Buffer &buf) override
    {
        ProtoContext::write_auth_string(std::string("foo"), buf);
        ProtoContext::write_auth_string(std::string("bar"), buf);
    }
    void server_auth(const std::string &username,
                     const SafeString &password,
                     const std::string &peer_info,
                     const AuthCert::Ptr &auth_cert) override
    {
        (void)username.size();
        (void)peer_info.size();
    }
    bool supports_epoch_data() override
    {
        return true;
    }
    void active(bool primary) override
    {
    }

    ProtoContext proto;
    std::deque<std::string> received;
    size_t n_sent = 0;
    std::vector<std::string> *record = nullptr; // seed generator only
};

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static InitProcess::Init init;
    if (size < 1)
        return 0;
    const bool server = !(data[0] & 4);
    const unsigned mode = data[0] & 3;
    data++;
    size--;

    // Fixed clock and RNG: the result depends only on the input.
    Time now = Time::from_seconds_since_epoch(1767225600);
    StrongRandomAPI::Ptr rng(new fuzz::FixedRand());
    Frame::Ptr frame = frame_init_simple(2048);
    SessionStats::Ptr stats(new FuzzStats);
    try
    {
        Peer peer(make_config(server, mode, now, frame, rng, stats), stats);
        peer.proto.reset();
        peer.proto.start();
        peer.proto.flush(true);

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
                const ProtoContext::PacketType pt = peer.proto.packet_type(buf);
                if (pt.is_control())
                    peer.proto.control_net_recv(pt, std::move(buf));
                else if (pt.is_data())
                    peer.proto.data_decrypt(pt, buf);
                peer.proto.flush(true);
                now += Time::Duration::milliseconds(100);
                if (peer.proto.now() >= peer.proto.next_housekeeping())
                    peer.proto.housekeeping();
            }
            catch (const std::exception &)
            {
            }
            if (peer.proto.invalidated())
                break;
        }
    }
    catch (const std::exception &)
    {
    }
    return 0;
}

#ifdef FUZZ_PROTO_SEEDGEN
// Seed generator (not part of the fuzz target): runs a client and a server of each configuration
// against each other in-process and writes what each side sent, framed as this harness's input, so
// the corpus starts with real HARD_RESET / ACK / TLS ClientHello / ServerHello packets.
#include <fstream>
int main(int argc, char **argv)
{
    static InitProcess::Init init;
    const std::string outdir = argc > 1 ? argv[1] : ".";
    for (unsigned mode = 0; mode < 4; ++mode)
    {
        Time now = Time::from_seconds_since_epoch(1767225600);
        StrongRandomAPI::Ptr crng(new fuzz::FixedRand()), srng(new fuzz::FixedRand());
        Frame::Ptr frame = frame_init_simple(2048);
        SessionStats::Ptr stats(new FuzzStats);
        Peer cli(make_config(false, mode, now, frame, crng, stats), stats);
        Peer srv(make_config(true, mode, now, frame, srng, stats), stats);
        std::vector<std::string> c2s, s2c, c2s_all, s2c_all;
        cli.record = &c2s;
        srv.record = &s2c;
        cli.proto.reset();
        srv.proto.reset();
        cli.proto.start();
        srv.proto.start();
        cli.proto.flush(true);
        for (int round = 0; round < 12; ++round)
        {
            auto deliver = [&](std::vector<std::string> &q, std::vector<std::string> &all, Peer &to) {
                std::vector<std::string> pkts;
                pkts.swap(q);
                for (auto &pk : pkts)
                {
                    all.push_back(pk);
                    BufferAllocated b;
                    frame->prepare(Frame::READ_LINK_UDP, b);
                    b.write(reinterpret_cast<const unsigned char *>(pk.data()), pk.size());
                    try
                    {
                        const ProtoContext::PacketType pt = to.proto.packet_type(b);
                        if (pt.is_control())
                            to.proto.control_net_recv(pt, std::move(b));
                        to.proto.flush(true);
                    }
                    catch (const std::exception &e)
                    {
                        std::cerr << "seedgen mode " << mode << ": " << e.what() << "\n";
                    }
                }
            };
            deliver(c2s, c2s_all, srv);
            deliver(s2c, s2c_all, cli);
            now += Time::Duration::milliseconds(100);
        }
        auto write_seed = [&](const std::vector<std::string> &pkts, bool client, size_t n) {
            std::string seed(1, static_cast<char>(mode | (client ? 4 : 0)));
            for (size_t i = 0; i < pkts.size() && i < n; ++i)
            {
                seed.push_back(static_cast<char>(pkts[i].size() >> 8));
                seed.push_back(static_cast<char>(pkts[i].size() & 0xff));
                seed += pkts[i];
            }
            std::ofstream(outdir + "/" + (client ? "client" : "server") + "-mode" + std::to_string(mode) + "-" + std::to_string(n), std::ios::binary) << seed;
        };
        // server-side seeds replay what the client sent; client-side seeds what the server sent
        for (size_t n : {1, 2, 4, 64})
        {
            write_seed(c2s_all, false, n);
            write_seed(s2c_all, true, n);
        }
        std::cerr << "mode " << mode << ": client sent " << c2s_all.size() << ", server sent " << s2c_all.size() << "\n";
    }
    return 0;
}
#endif
