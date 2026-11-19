// HTTP proxy authentication driven by the proxy's reply: the Proxy-Authenticate header
// (HTTPProxy::ProxyAuthenticate), the NTLM phase-2 challenge -> phase-3 response (NTLM::phase_3:
// base64 decode, target-info security buffers) and the Digest response computation.
#include "fuzz_common.hpp"
#include <openvpn/ssl/sslchoose.hpp>
#include <openvpn/crypto/cryptoalgs.hpp>
#include <openvpn/crypto/digestapi.hpp>
#include <openvpn/random/mtrandapi.hpp>
#include <openvpn/proxy/proxyauth.hpp>
#include <openvpn/proxy/ntlm.hpp>
#include <openvpn/proxy/httpdigest.hpp>

#include <openvpn/init/initprocess.hpp>

using namespace openvpn;

namespace {
// Deterministic "strong" RNG so each input's result depends only on the input.
class FixedRand : public StrongRandomAPI
{
  public:
    std::string name() const override { return "FixedRand"; }
    void rand_bytes(unsigned char *buf, size_t size) override { std::memset(buf, 0x5a, size); }
    bool rand_bytes_noexcept(unsigned char *buf, size_t size) override
    {
        rand_bytes(buf, size);
        return true;
    }
};
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static InitProcess::Init init; // sets up the process-wide base64 codec, among others
    static DigestFactory::Ptr df(new CryptoDigestFactory<SSLLib::CryptoAPI>());
    const std::string s(reinterpret_cast<const char *>(data), size);
    try
    {
        HTTPProxy::ProxyAuthenticate pa(s);
        (void)pa.to_string();
        const std::string realm = pa.parms.get_value("realm");
        const std::string nonce = pa.parms.get_value("nonce");
        const std::string algorithm = pa.parms.get_value("algorithm");
        const std::string qop = pa.parms.get_value("qop");
        if (string::strcasecmp(pa.method, "digest") == 0)
        {
            const std::string ha1 = HTTPProxy::Digest::calcHA1(*df, algorithm, "user", realm, "pass", nonce, "0a4f113b");
            (void)HTTPProxy::Digest::calcResponse(*df, ha1, nonce, "00000001", "0a4f113b", qop, "CONNECT", "host:443", "");
        }
    }
    catch (const std::exception &)
    {
    }
    try
    {
        FixedRand rng;
        (void)HTTPProxy::NTLM::phase_3(*df, s, "DOMAIN\\user", "password", rng);
    }
    catch (const std::exception &)
    {
    }
    return 0;
}
