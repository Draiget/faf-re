#pragma once

#include <cstddef>
#include <cstdio>
#include <stdexcept>

#include "boost/shared_ptr.h"
#include "gpg/core/containers/String.h"
#include "lua/LuaObject.h"
#include "legacy/containers/String.h"
#include "moho/misc/ISaveRequest.h"

namespace gpg
{
  class WriteArchive;
}

namespace moho
{
  /**
   * Address context:
   * - `boost::detail::sp_counted_impl_pd<_iobuf*,Moho::SFileStarCloser>`
   *
   * What it does:
   * Closes `FILE*` handles owned by save-request shared pointers.
   */
  struct SFileStarCloser
  {
    void operator()(std::FILE* file) const noexcept;
  };

  /**
   * Exception payload used by legacy save/load codepaths.
   */
  class SaveLoadError : public std::runtime_error
  {
  public:
    /**
     * Address: 0x0087FDC0 (FUN_0087FDC0, Moho::SaveLoadError::SaveLoadError)
     *
     * What it does:
     * Builds the formatted runtime-error message and stores the raw save/load
     * message fragment for later reporting.
     */
    explicit SaveLoadError(const char* message);

    /**
     * Address: 0x00880700 (FUN_00880700, Moho::SaveLoadError::SaveLoadError copy-ctor)
     *
     * What it does:
     * Copies base exception payload and duplicated save/load message fragment.
     */
    SaveLoadError(const SaveLoadError& other);

    /**
     * Address: 0x0087FE90 (FUN_0087FE90, Moho::SaveLoadError::~SaveLoadError)
     *
     * What it does:
     * Releases saved message storage then tears down `std::runtime_error`
     * and `std::exception` lanes.
     */
    ~SaveLoadError() noexcept override;

    [[nodiscard]] const msvc8::string& GetRawMessage() const noexcept;

  private:
    msvc8::string mRawMessage;
  };

  /**
   * Concrete save-game request object consumed by sim dispatch/save loop.
   *
   * VFTABLE: 0x00E49D8C
   * Base: `ISaveRequest`
   * Size: 0x5C
   */
  class CSaveGameRequestImpl final : public ISaveRequest
  {
  public:
    /**
     * Address: 0x00880EF0 (FUN_00880EF0)
     *
     * What it does:
     * Returns the write archive that receives serialized sim data.
     */
    gpg::WriteArchive* GetArchive() override;

    /**
     * Address: 0x008813A0 (FUN_008813A0)
     *
     * What it does:
     * Finalizes save output, writes fixed file header payload, and dispatches
     * completion callback state.
     */
    void Save(const SSaveGameDispatchData& data) override;

    /**
     * Address: 0x00880F00 (FUN_00880F00)
     *
     * gpg::StrArg,gpg::StrArg,LuaPlus::LuaObject const &
     *
     * What it does:
     * Initializes one save request object, opens `<savePath>.NEW`, writes the
     * placeholder file header block, and serializes `SSavedGameHeader`.
     */
    CSaveGameRequestImpl(gpg::StrArg savePath, gpg::StrArg sessionName, const LuaPlus::LuaObject& completionCallback);

    /**
     * Address: 0x008819E0 (FUN_008819E0)
     *
     * What it does:
     * Releases active write archive, shared file handle, and callback/string fields.
     */
    ~CSaveGameRequestImpl();

  private:
    msvc8::string mSavePath;                    // +0x04
    msvc8::string mSessionName;                 // +0x20
    LuaPlus::LuaObject mCompletionCallback;     // +0x3C
    boost::shared_ptr<std::FILE> mFile;         // +0x50
    gpg::WriteArchive* mArchive = nullptr;      // +0x58
  };

  static_assert(sizeof(boost::shared_ptr<std::FILE>) == 0x8, "shared_ptr<FILE> size must be 0x8");
  static_assert(sizeof(CSaveGameRequestImpl) == 0x5C, "CSaveGameRequestImpl size must be 0x5C");
} // namespace moho
