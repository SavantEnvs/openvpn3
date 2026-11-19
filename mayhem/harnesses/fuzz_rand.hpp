// Deterministic RNG for the protocol harnesses: each input reseeds it, so the keys, session IDs
// and nonces openvpn3 draws are the same every time an input is replayed.
#pragma once
#include <openvpn/random/randapi.hpp>
#include <random>

namespace fuzz {
class FixedRand : public openvpn::StrongRandomAPI
{
  public:
    using Ptr = openvpn::RCPtr<FixedRand>;
    static constexpr std::uint64_t kDefaultSeed = 0x6f76706e33ULL;
    explicit FixedRand(std::uint64_t seed = kDefaultSeed)
        : gen_(seed)
    {
    }
    // For an RNG kept across inputs (fuzz_psid_cookie's long-lived config): back to the start.
    void reseed(std::uint64_t seed = kDefaultSeed)
    {
        gen_.seed(seed);
    }
    std::string name() const override
    {
        return "FixedRand";
    }
    void rand_bytes(unsigned char *buf, size_t size) override
    {
        for (size_t i = 0; i < size; ++i)
            buf[i] = static_cast<unsigned char>(gen_());
    }
    bool rand_bytes_noexcept(unsigned char *buf, size_t size) override
    {
        rand_bytes(buf, size);
        return true;
    }

  private:
    std::mt19937_64 gen_;
};
} // namespace fuzz
