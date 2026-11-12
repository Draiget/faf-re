// The Vulkan pipeline cache file (gpg/gal/backends/vulkan/PipelineCacheVulkan.h): a saved cache is handed to the
// driver only when its header names this device and driver, and temporary files a process left mid-write are removed
// once they are old, never while another process may still be writing them.

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "gpg/gal/PipelineDiskCache.h"
#include "gpg/gal/backends/vulkan/PipelineCacheVulkan.h"

namespace
{
  class VulkanPipelineCacheFile : public ::testing::Test
  {
  protected:
    void SetUp() override
    {
      mFolder = std::filesystem::temp_directory_path() /
        ("faf_vulkan_cache_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
      std::filesystem::create_directories(mFolder);
      gpg::gal::gPipelineDiskCache = true;
      mProperties.vendorID = 0x10DEU;
      mProperties.deviceID = 0x1E02U;
      for (std::uint32_t index = 0U; index < VK_UUID_SIZE; ++index) {
        mProperties.pipelineCacheUUID[index] = static_cast<std::uint8_t>(index * 7U + 1U);
      }
    }

    void TearDown() override
    {
      std::error_code error;
      std::filesystem::remove_all(mFolder, error);
    }

    [[nodiscard]] std::string Directory() const
    {
      return mFolder.string() + "/";
    }

    /** A cache file: the header for `properties`, then `payload` bytes. */
    void WriteCache(
      const VkPhysicalDeviceProperties& properties,
      const std::size_t payload
    ) const
    {
      VkPipelineCacheHeaderVersionOne header{};
      header.headerSize = sizeof(header);
      header.headerVersion = VK_PIPELINE_CACHE_HEADER_VERSION_ONE;
      header.vendorID = properties.vendorID;
      header.deviceID = properties.deviceID;
      std::memcpy(header.pipelineCacheUUID, properties.pipelineCacheUUID, VK_UUID_SIZE);
      std::vector<std::uint8_t> bytes(sizeof(header) + payload, 0xABU);
      std::memcpy(bytes.data(), &header, sizeof(header));
      std::ofstream file(mFolder / "pipelines-vulkan.bin", std::ios::binary);
      file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }

    std::filesystem::path mFolder;
    VkPhysicalDeviceProperties mProperties{};
  };
} // namespace

TEST_F(
  VulkanPipelineCacheFile,
  ACacheFromThisDeviceIsHandedOn
)
{
  WriteCache(mProperties, 100U);
  gpg::gal::vulkan::PipelineCacheFile cache;
  EXPECT_EQ(cache.Open(mProperties, Directory()).size(), sizeof(VkPipelineCacheHeaderVersionOne) + 100U);
}

TEST_F(
  VulkanPipelineCacheFile,
  ACacheFromAnotherDeviceOrDriverIsDropped
)
{
  VkPhysicalDeviceProperties other = mProperties;
  other.deviceID += 1U;
  WriteCache(other, 100U);
  gpg::gal::vulkan::PipelineCacheFile cache;
  EXPECT_TRUE(cache.Open(mProperties, Directory()).empty());

  other = mProperties;
  other.pipelineCacheUUID[3] ^= 0xFFU; // another driver version
  WriteCache(other, 100U);
  EXPECT_TRUE(cache.Open(mProperties, Directory()).empty());
}

TEST_F(
  VulkanPipelineCacheFile,
  ADamagedOrMissingFileGivesNothing
)
{
  gpg::gal::vulkan::PipelineCacheFile cache;
  EXPECT_TRUE(cache.Open(mProperties, Directory()).empty()); // no file yet
  {
    std::ofstream file(mFolder / "pipelines-vulkan.bin", std::ios::binary);
    file << "short";
  }
  EXPECT_TRUE(cache.Open(mProperties, Directory()).empty());
}

TEST_F(
  VulkanPipelineCacheFile,
  OnlyOldTemporariesAreRemoved
)
{
  const std::filesystem::path old = mFolder / "pipelines-vulkan.bin.111.tmp";
  const std::filesystem::path fresh = mFolder / "pipelines-vulkan.bin.222.tmp";
  const std::filesystem::path other = mFolder / "unrelated.111.tmp";
  for (const std::filesystem::path& path : {old, fresh, other}) {
    std::ofstream(path) << "x";
  }
  const auto hourAgo = std::filesystem::file_time_type::clock::now() - std::chrono::hours(1);
  std::filesystem::last_write_time(old, hourAgo);
  std::filesystem::last_write_time(other, hourAgo);

  gpg::gal::vulkan::PipelineCacheFile cache;
  (void)cache.Open(mProperties, Directory());

  EXPECT_FALSE(std::filesystem::exists(old));
  EXPECT_TRUE(std::filesystem::exists(fresh)); // another process may still be writing it
  EXPECT_TRUE(std::filesystem::exists(other));
}

TEST_F(
  VulkanPipelineCacheFile,
  TheSwitchOffKeepsTheFileOut
)
{
  WriteCache(mProperties, 100U);
  gpg::gal::gPipelineDiskCache = false;
  gpg::gal::vulkan::PipelineCacheFile cache;
  EXPECT_TRUE(cache.Open(mProperties, Directory()).empty());
  gpg::gal::gPipelineDiskCache = true;
}
