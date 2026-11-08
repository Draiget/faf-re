// CZipFile reads an entry whose data starts at or past 2 GiB, as the binary does (PR #291).
//
// The binary's ReadZipDirectory (0x0046C960) keeps an entry's data offset as 32 unsigned bits: it
// compares the cache with -1 (0x0046C97C), seeks with a zero high word (0x0046C981, 0x0046CA68) and
// stores the offset without a range check (0x0046CA06). Each test writes a sparse archive, so the gap
// before the entry takes no disk space, and reads the entry twice: once through its local header and
// once from the cached offset.
//
// usage: faf_zip_offset_tests

#include <Windows.h>
#include <winioctl.h>

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <string>
#include <system_error>
#include <gtest/gtest.h>

#include "moho/misc/CZipFile.h"

namespace
{
  constexpr std::uint32_t kLocalHeaderSize = 30u;
  constexpr std::uint32_t kCentralHeaderSize = 46u;
  constexpr std::uint16_t kDosDate1980 = 0x0021u;

  void Put16(std::string& out, const std::uint16_t value)
  {
    out.push_back(static_cast<char>(value & 0xFFu));
    out.push_back(static_cast<char>(value >> 8));
  }

  void Put32(std::string& out, const std::uint32_t value)
  {
    Put16(out, static_cast<std::uint16_t>(value & 0xFFFFu));
    Put16(out, static_cast<std::uint16_t>(value >> 16));
  }

  [[nodiscard]] std::uint32_t Crc32(const std::string& bytes)
  {
    std::uint32_t crc = 0xFFFFFFFFu;
    for (const char byte : bytes) {
      crc ^= static_cast<unsigned char>(byte);
      for (int bit = 0; bit < 8; ++bit) {
        crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
      }
    }
    return ~crc;
  }

  // One stored entry whose data starts at `dataOffset`, then the central directory and its end record.
  [[nodiscard]] std::string ArchiveTail(const std::uint32_t dataOffset, const std::string& name, const std::string& payload)
  {
    const std::uint32_t localOffset = dataOffset - kLocalHeaderSize - static_cast<std::uint32_t>(name.size());
    const std::uint32_t size = static_cast<std::uint32_t>(payload.size());
    const std::uint32_t crc = Crc32(payload);
    const auto nameLength = static_cast<std::uint16_t>(name.size());

    std::string out;
    Put32(out, 0x04034B50u); // local file header
    Put16(out, 20u);
    Put16(out, 0u);
    Put16(out, 0u); // stored
    Put16(out, 0u);
    Put16(out, kDosDate1980);
    Put32(out, crc);
    Put32(out, size);
    Put32(out, size);
    Put16(out, nameLength);
    Put16(out, 0u);
    out += name;
    out += payload;

    Put32(out, 0x02014B50u); // central directory file header
    Put16(out, 20u);
    Put16(out, 20u);
    Put16(out, 0u);
    Put16(out, 0u);
    Put16(out, 0u);
    Put16(out, kDosDate1980);
    Put32(out, crc);
    Put32(out, size);
    Put32(out, size);
    Put16(out, nameLength);
    Put16(out, 0u);
    Put16(out, 0u);
    Put16(out, 0u);
    Put16(out, 0u);
    Put32(out, 0u);
    Put32(out, localOffset);
    out += name;

    Put32(out, 0x06054B50u); // end of central directory
    Put16(out, 0u);
    Put16(out, 0u);
    Put16(out, 1u);
    Put16(out, 1u);
    Put32(out, kCentralHeaderSize + nameLength);
    Put32(out, dataOffset + size);
    Put16(out, 0u);
    return out;
  }

  class ZipOffset : public ::testing::TestWithParam<std::uint32_t>
  {
  protected:
    void SetUp() override
    {
      mPath = std::filesystem::temp_directory_path() /
              ("faf_zip_offset_" + std::to_string(GetCurrentProcessId()) + "_" + std::to_string(GetParam()) + ".zip");
      // Every read goes to the archive, so the second one seeks from the cached offset.
      moho::CZipFile::SetKeepEntryData(false);
    }

    void TearDown() override
    {
      // Back to the build's default (CZipFile.cpp: x86 keeps the bytes, as the binary does; x64 doesn't).
#if defined(_M_IX86)
      moho::CZipFile::SetKeepEntryData(true);
#else
      moho::CZipFile::SetKeepEntryData(false);
#endif
      std::error_code error;
      std::filesystem::remove(mPath, error);
    }

    // False when the file system can't hold a sparse file: the test is skipped rather than writing gigabytes.
    [[nodiscard]] bool WriteSparse(const std::uint64_t offset, const std::string& bytes) const
    {
      const HANDLE file = CreateFileW(
        mPath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr
      );
      if (file == INVALID_HANDLE_VALUE) {
        return false;
      }
      DWORD returned = 0;
      bool written = DeviceIoControl(file, FSCTL_SET_SPARSE, nullptr, 0, nullptr, 0, &returned, nullptr) != 0;
      LARGE_INTEGER position{};
      position.QuadPart = static_cast<LONGLONG>(offset);
      written = written && SetFilePointerEx(file, position, nullptr, FILE_BEGIN) != 0;
      DWORD count = 0;
      written = written && WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr) != 0 &&
                count == bytes.size();
      CloseHandle(file);
      return written;
    }

    std::filesystem::path mPath;
  };

  TEST_P(ZipOffset, ReadsEntryFreshAndFromCachedOffset)
  {
    const std::uint32_t dataOffset = GetParam();
    const std::string name = "lua/zip_offset.lua";
    const std::string payload = "-- data at " + std::to_string(dataOffset) + "\n";
    const std::string tail = ArchiveTail(dataOffset, name, payload);
    const std::uint64_t tailOffset = dataOffset - kLocalHeaderSize - name.size();
    if (!WriteSparse(tailOffset, tail)) {
      GTEST_SKIP() << "can't write a sparse file in " << mPath.parent_path().string();
    }

    const std::string path = mPath.string();
    moho::CZipFile archive(path.c_str());
    ASSERT_EQ(archive.mEntries.size(), 1u);
    const moho::CZipFileEntry& entry = *archive.mEntries[0].mEntry.get();
    EXPECT_EQ(entry.mCachedDataOffset, -1);

    for (int read = 0; read < 2; ++read) {
      SCOPED_TRACE(read == 0 ? "through the local header" : "from the cached offset");
      const gpg::MemBuffer<const char> bytes = archive.ReadEntry(0);
      ASSERT_NE(bytes.data(), nullptr);
      EXPECT_EQ(std::string(bytes.data(), bytes.Size()), payload);
      EXPECT_EQ(static_cast<std::uint32_t>(entry.mCachedDataOffset), dataOffset);
      EXPECT_EQ(entry.mLocalHeaderOffset, static_cast<std::uint32_t>(tailOffset));
    }
  }

  // Below 2 GiB, the first offset with the sign bit set (master marked it invalid), and the
  // highest that leaves room for the payload and the directory under 4 GiB.
  // GoogleTest 1.15's macro keeps the name generator in a tuple it never reads (-Wunused-variable).
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-variable"
  INSTANTIATE_TEST_SUITE_P(
    DataOffsets, ZipOffset, ::testing::Values(0x00000100u, 0x7FFFFF00u, 0x80000000u, 0xFFFFFF00u),
    [](const ::testing::TestParamInfo<std::uint32_t>& info) {
      char text[16];
      std::snprintf(text, sizeof(text), "At%08X", info.param);
      return std::string(text);
    }
  );
#pragma clang diagnostic pop
} // namespace
