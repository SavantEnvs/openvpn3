// Shared prelude for the openvpn3 fuzz harnesses (mayhem/harnesses/*.cpp).
// openvpn3 is header-only: each harness includes the headers it fuzzes after this file.
// Logging goes to a discarding stream so the fuzzer is not slowed down by stdout.
#pragma once
#include <cstddef>
#include <cstdint>
#include <ostream>
#include <streambuf>
#include <string>

namespace fuzz {
class NullBuf : public std::streambuf
{
  protected:
    int overflow(int c) override { return c; }
    std::streamsize xsputn(const char *, std::streamsize n) override { return n; }
};
inline std::ostream &null_stream()
{
    static NullBuf nb;
    static std::ostream os(&nb);
    return os;
}
} // namespace fuzz

#ifndef OPENVPN_LOG_STREAM
#define OPENVPN_LOG_STREAM fuzz::null_stream()
#endif

#include <openvpn/io/io.hpp>
#include <openvpn/log/logsimple.hpp>
