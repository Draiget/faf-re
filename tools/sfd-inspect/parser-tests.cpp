#include "moho/movie/sfd/SfdHeaderParser.h"
#include <cstring>
#include <iostream>
#include <random>
#include <stdexcept>
#include <vector>
using namespace moho::sfd;
namespace
{
  void Require(
    bool value
  )
  {
    if (!value)
      throw std::runtime_error("Parser invariant failed");
  }
  std::vector<std::byte> Fixture(
    std::size_t base
  )
  {
    std::vector<std::byte> bytes(base + 2048);
    auto put = [&](std::size_t offset, unsigned value) {
      bytes[base + offset] = static_cast<std::byte>(value);
    };
    std::memcpy(bytes.data() + base + 32, "SofdecStream            ", 24);
    put(0x81, 8);
    put(0x88, 2);
    put(0x8d, 8);
    put(0xb0, 2);
    put(0xb2, 1);
    put(0xb3, 1);
    put(0xc0, 150);
    put(0x180 + 24, 0xbf);
    put(0x1c0 + 24, 0xe0);
    put(0x1c0 + 28, 12);
    put(0x1c0 + 29, 0);
    put(0x1c0 + 30, 192);
    put(0x1c0 + 31, 4);
    return bytes;
  }
} // namespace
int main()
{
  try {
    HeaderInfo h;
    for (std::size_t base : {0U, 37U, 2048U, 4096U, 8192U}) {
      auto bytes = Fixture(base);
      Require(ParseSfdHeader(bytes, h));
      Require(h.width == 192 && h.height == 192 && h.frameCount == 150 && h.fpsMilli == 29970);
      for (std::size_t n = 0; n < base + 0x200; ++n)
        Require(!ParseSfdHeader(std::span(bytes).first(n), h));
      for (unsigned effect : {1U, 3U, 6U}) {
        bytes[base + 0x1c0 + 39] = static_cast<std::byte>(effect);
        Require(ParseSfdHeader(bytes, h));
        Require(h.compositionMode == (effect == 1 ? 33 : effect == 3 ? 81 : 97));
      }
      bytes[base + 55] = std::byte{'!'};
      Require(!ParseSfdHeader(bytes, h));
    }
    auto bytes = Fixture(0);
    for (const auto offset : {0xb0, 0xb1, 0xb2, 0xb3, 0x84, 0x88, 0x1df}) {
      auto bad = bytes;
      bad[offset] = std::byte{255};
      Require(!ParseSfdHeader(bad, h));
      Require(h.width == 0);
    }
    std::mt19937 random(873);
    for (int i = 0; i < 20000; ++i) {
      std::vector<std::byte> input(random() % 8192);
      for (auto& b : input)
        b = static_cast<std::byte>(random());
      if (i % 2 == 0 && input.size() >= bytes.size())
        std::copy(bytes.begin(), bytes.end(), input.begin());
      for (int j = 0; j < 10 && !input.empty(); ++j)
        input[random() % input.size()] = static_cast<std::byte>(random());
      (void)ParseSfdHeader(input, h);
    }
    std::cout << "Parser truncation, relocation, malformed metadata and 20000 fuzz cases PASS\n";
  } catch (const std::exception& e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
