#include "ReflectionTestSupport.h"

#include <atomic>
#include <cstdio>
#include <memory>
#include <sstream>
#include <system_error>

#include "boost/shared_ptr.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "platform/Platform.h"

namespace faf_reflection_tests
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

    std::atomic<unsigned int> gFolderCounter{0u};

    void CloseFile(std::FILE* const file)
    {
      if (file != nullptr) {
        std::fclose(file);
      }
    }

    boost::shared_ptr<std::FILE> OpenFile(const std::string& path, const char* const mode)
    {
      std::FILE* file = nullptr;
      EXPECT_EQ(fopen_s(&file, path.c_str(), mode), 0) << path;
      return boost::shared_ptr<std::FILE>(file, &CloseFile);
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

    class StringSink final : public gpg::WriteArchiveSink
    {
    public:
      [[nodiscard]] bool Write(const void* const bytes, const std::size_t byteCount) override
      {
        mBytes.append(static_cast<const char*>(bytes), byteCount);
        return true;
      }
      std::string mBytes;
    };
  } // namespace

  std::string ToHex(const std::string& bytes)
  {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2u);
    for (const char byte : bytes) {
      const auto value = static_cast<unsigned char>(byte);
      out.push_back(kDigits[value >> 4]);
      out.push_back(kDigits[value & 0x0Fu]);
    }
    return out;
  }

  ArchiveFixture::ArchiveFixture()
  {
    const std::string name = "faf_reflection_tests_" + std::to_string(::GetCurrentProcessId()) + "_" +
                             std::to_string(gFolderCounter.fetch_add(1u));
    mFolder = std::filesystem::temp_directory_path() / name;
    std::error_code error;
    std::filesystem::remove_all(mFolder, error);
    std::filesystem::create_directories(mFolder, error);
    EXPECT_FALSE(error) << "cannot create " << mFolder.string() << ": " << error.message();
  }

  ArchiveFixture::~ArchiveFixture()
  {
    std::error_code error;
    std::filesystem::remove_all(mFolder, error);
  }

  std::string ArchiveFixture::NextFile(const char* const prefix)
  {
    return (mFolder / (std::string(prefix) + std::to_string(mCount++) + ".bin")).string();
  }

  std::string ArchiveFixture::Write(const std::function<void(gpg::WriteArchive&)>& body, const WriterKind kind)
  {
    if (kind == WriterKind::FastSink) {
      StringSink sink;
      {
        std::unique_ptr<gpg::WriteArchive> archive(gpg::CreateFastBinaryWriteArchive(sink));
        body(*archive);
        archive->Close();
      }
      return sink.mBytes;
    }

    const std::string path = NextFile("written");
    {
      boost::shared_ptr<std::FILE> file = OpenFile(path, "wb");
      std::unique_ptr<gpg::WriteArchive> archive(gpg::CreateBinaryWriteArchive(file));
      body(*archive);
      archive->Close();
    }
    return ReadWholeFile(path);
  }

  void ArchiveFixture::Read(const std::string& bytes, const std::function<void(gpg::ReadArchive&)>& body)
  {
    const std::string path = NextFile("read");
    WriteWholeFile(path, bytes);
    boost::shared_ptr<std::FILE> file = OpenFile(path, "rb");
    std::unique_ptr<gpg::ReadArchive> archive(gpg::CreateBinaryReadArchive(file));
    body(*archive);
  }

  std::string ArchiveFixture::WriteText(const std::function<void(gpg::WriteArchive&)>& body)
  {
    auto* const text = new std::ostringstream;
    const boost::shared_ptr<std::ostream> stream(text);
    {
      std::unique_ptr<gpg::WriteArchive> archive(gpg::CreateTextWriteArchive(stream));
      body(*archive);
      archive->Close();
    }
    return text->str();
  }

  void ArchiveFixture::ReadText(const std::string& text, const std::function<void(gpg::ReadArchive&)>& body)
  {
    const boost::shared_ptr<std::istream> stream(new std::istringstream(text));
    std::unique_ptr<gpg::ReadArchive> archive(gpg::CreateTextReadArchive(stream));
    body(*archive);
  }
} // namespace faf_reflection_tests
