#include "CoreTestSupport.h"

#include <atomic>
#include <cstdio>
#include <gtest/gtest.h>

#include "gpg/core/utils/Global.h"
#include "platform/Platform.h"

namespace faf_core_tests
{
  namespace
  {
    // `HandleAssertFailure` hands its message to the die handler and returns when none is set, so an engine
    // assertion inside a test would pass unseen. This handler turns it into a test failure.
    void FailOnEngineAssertion(const char* const message)
    {
      ADD_FAILURE() << "engine assertion: " << (message != nullptr ? message : "(null)");
    }

    class EngineAssertEnvironment final : public ::testing::Environment
    {
    public:
      void SetUp() override { mPrevious = gpg::SetDieHandler(&FailOnEngineAssertion); }
      void TearDown() override { (void)gpg::SetDieHandler(mPrevious); }

    private:
      gpg::die_handler_t mPrevious = nullptr;
    };

    [[maybe_unused]] ::testing::Environment* const gEngineAssertEnvironment =
      ::testing::AddGlobalTestEnvironment(new EngineAssertEnvironment);

    std::atomic<unsigned int> gTempDirCounter{0u};
  } // namespace

  TempDir::TempDir()
  {
    const std::string name = "faf_core_tests_" + std::to_string(::GetCurrentProcessId()) + "_" +
                             std::to_string(gTempDirCounter.fetch_add(1u));
    mPath = std::filesystem::temp_directory_path() / name;
    std::error_code error;
    std::filesystem::remove_all(mPath, error);
    std::filesystem::create_directories(mPath, error);
    EXPECT_FALSE(error) << "cannot create " << mPath.string() << ": " << error.message();
  }

  TempDir::~TempDir()
  {
    std::error_code error;
    std::filesystem::remove_all(mPath, error);
  }

  std::string PatternBytes(const std::size_t size, std::uint32_t seed)
  {
    std::string bytes(size, '\0');
    for (std::size_t index = 0; index < size; ++index) {
      seed = seed * 1664525u + 1013904223u;
      bytes[index] = static_cast<char>(seed >> 24);
    }
    return bytes;
  }

  std::string ReadWholeFile(const std::string& path)
  {
    std::string bytes;
    std::FILE* file = nullptr;
    if (fopen_s(&file, path.c_str(), "rb") != 0 || file == nullptr) {
      ADD_FAILURE() << "cannot open " << path;
      return bytes;
    }
    char chunk[4096];
    for (;;) {
      const std::size_t got = std::fread(chunk, 1u, sizeof(chunk), file);
      bytes.append(chunk, got);
      if (got < sizeof(chunk)) {
        break;
      }
    }
    std::fclose(file);
    return bytes;
  }

  void WriteWholeFile(const std::string& path, const std::string& bytes)
  {
    std::FILE* file = nullptr;
    if (fopen_s(&file, path.c_str(), "wb") != 0 || file == nullptr) {
      ADD_FAILURE() << "cannot create " << path;
      return;
    }
    if (!bytes.empty()) {
      EXPECT_EQ(std::fwrite(bytes.data(), 1u, bytes.size(), file), bytes.size());
    }
    std::fclose(file);
  }

  std::string ToHex(const void* const data, const std::size_t size)
  {
    static constexpr char kDigits[] = "0123456789abcdef";
    const auto* const bytes = static_cast<const unsigned char*>(data);
    std::string out;
    out.reserve(size * 2u);
    for (std::size_t index = 0; index < size; ++index) {
      out.push_back(kDigits[bytes[index] >> 4]);
      out.push_back(kDigits[bytes[index] & 0x0Fu]);
    }
    return out;
  }
} // namespace faf_core_tests
