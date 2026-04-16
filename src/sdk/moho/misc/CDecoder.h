#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/Stream.h"
#include "legacy/containers/AutoPtr.h"
#include "moho/command/ICommandSink.h"
#include "moho/net/IMessageReceiver.h"

namespace LuaPlus
{
  class LuaObject;
  class LuaState;
} // namespace LuaPlus

namespace moho
{
  class RRuleGameRules;
  struct SSTITarget;
  struct SSTICommandIssueData;
  struct SOCellPos;

  /**
   * VFTABLE: 0x00E2E748
   * COL:  0x00E884A8
   *
   * Command-stream decoder that receives wire messages and forwards decoded
   * payloads to `ICommandSink`.
   */
  class CDecoder final : public IMessageReceiver
  {
  public:
    /**
     * Address: 0x006E4060 (FUN_006E4060)
     * Mangled:
     * ??0CDecoder@Moho@@QAE@PAVICommandSink@1@AAV?$auto_ptr@VStream@gpg@@@std@@PAVRRuleGameRules@1@PAVLuaState@LuaPlus@@@Z
     *
     * What it does:
     * Initializes receiver links, steals optional stream ownership, and stores
     * sink/rules/lua decode dependencies.
     */
    CDecoder(
      msvc8::auto_ptr<gpg::Stream>& stream, ICommandSink* sink, RRuleGameRules* rules, LuaPlus::LuaState* luaState
    );

    /**
     * Address: 0x006E40A0 (FUN_006E40A0)
     * Mangled: ??1CDecoder@Moho@@QAE@XZ
     *
     * What it does:
     * Releases owned decode stream and unlinks receiver attachments.
     */
    ~CDecoder();

    /**
     * Address: 0x006E40F0 (FUN_006E40F0)
     * Mangled: ?ProcessMessage@CDecoder@Moho@@UAEXABVCMessage@2@PAVCMessageDispatcher@2@@Z
     *
     * What it does:
     * Appends incoming wire bytes into owned stream (if present) and dispatches
     * decode by opcode.
     */
    void ReceiveMessage(CMessage* message, CMessageDispatcher* dispatcher) override;

  private:
    /**
     * Address: 0x006E4150 (FUN_006E4150 thunk) -> 0x0128F810 (FUN_0128F810)
     *
     * What it does:
     * Builds a read-only message stream view and dispatches command-opcode decode.
     */
    void DecodeMessage(const CMessage& message);

    /**
     * Address: 0x0128CC00 (FUN_0128CC00, Moho__CDecoder__DecodeMessage)
     *
     * What it does:
     * Patched minimal decode lane that accepts only command opcodes
     * `CMDST_Advance` and `CMDST_SetCommandSource`.
     */
    void DecodeMessagePatched(const CMessage& message);

    /**
     * Address: 0x006E4400 (FUN_006E4400)
     */
    void DecodeAdvance(gpg::BinaryReader& reader);
    /**
     * Address: 0x006E4440 (FUN_006E4440)
     */
    void DecodeSetCommandSource(gpg::BinaryReader& reader);
    /**
     * Address: 0x006E4470 (FUN_006E4470)
     *
     * What it does:
     * Forwards `CMDST_CommandSourceTerminated` directly to the configured
     * command sink.
     */
    void DecodeCommandSourceTerminated(gpg::BinaryReader& reader);
    /**
     * Address: 0x006E4480 (FUN_006E4480)
     */
    void DecodeVerifyChecksum(gpg::BinaryReader& reader);
    /**
     * Address: 0x006E44C0 (FUN_006E44C0)
     *
     * What it does:
     * Forwards `CMDST_RequestPause` directly to the configured command sink.
     */
    void DecodeRequestPause(gpg::BinaryReader& reader);
    /**
     * Address: 0x006E44D0 (FUN_006E44D0)
     *
     * What it does:
     * Forwards `CMDST_Resume` directly to the configured command sink.
     */
    void DecodeResume(gpg::BinaryReader& reader);
    /**
     * Address: 0x006E44E0 (FUN_006E44E0)
     *
     * What it does:
     * Forwards `CMDST_SingleStep` directly to the configured command sink.
     */
    void DecodeSingleStep(gpg::BinaryReader& reader);
    /**
     * Address: 0x006E44F0 (FUN_006E44F0)
     */
    void DecodeCreateUnit(gpg::BinaryReader& reader);
    /**
     * Address: 0x006E45D0 (FUN_006E45D0)
     */
    void DecodeCreateProp(gpg::BinaryReader& reader);
    /**
     * Address: 0x006E4670 (FUN_006E4670)
     */
    void DecodeDestroyEntity(gpg::BinaryReader& reader);
    /**
     * Address: 0x006E46A0 (FUN_006E46A0)
     */
    void DecodeWarpEntity(gpg::BinaryReader& reader);
    /**
     * Address: 0x006E46E0 (FUN_006E46E0)
     */
    void DecodeProcessInfoPair(gpg::BinaryReader& reader);
    /**
     * Address: 0x006E47D0 (FUN_006E47D0)
     */
    void DecodeIssueCommand(gpg::BinaryReader& reader);
    /**
     * Address: 0x006E48E0 (FUN_006E48E0)
     */
    void DecodeIssueFactoryCommand(gpg::BinaryReader& reader);
    /**
     * Address: 0x006E49F0 (FUN_006E49F0)
     */
    void DecodeIncreaseCommandCount(gpg::BinaryReader& reader);
    /**
     * Address: 0x006E4A30 (FUN_006E4A30)
     */
    void DecodeDecreaseCommandCount(gpg::BinaryReader& reader);
    /**
     * Address: 0x006E4A70 (FUN_006E4A70)
     */
    void DecodeSetCommandTarget(gpg::BinaryReader& reader);
    /**
     * Address: 0x006E4AC0 (FUN_006E4AC0)
     */
    void DecodeSetCommandType(gpg::BinaryReader& reader);
    /**
     * Address: 0x006E4B00 (FUN_006E4B00)
     */
    void DecodeSetCommandCells(gpg::BinaryReader& reader);
    /**
     * Address: 0x006E4BB0 (FUN_006E4BB0)
     */
    void DecodeRemoveCommandFromQueue(gpg::BinaryReader& reader);
    /**
     * Address: 0x006E4BF0 (FUN_006E4BF0)
     */
    void DecodeExecuteLuaInSim(gpg::BinaryReader& reader);
    /**
     * Address: 0x006E4CA0 (FUN_006E4CA0)
     */
    void DecodeLuaSimCallback(gpg::BinaryReader& reader);
    /**
     * Address: 0x006E4D80 (FUN_006E4D80)
     */
    void DecodeDebugCommand(gpg::BinaryReader& reader);
    /**
     * Address: 0x006E4E70 (FUN_006E4E70)
     */
    void DecodeEndGame();

    /**
     * Address: 0x006E4E90 (FUN_006E4E90 / FUN_006E4F30 / FUN_006E4FC0)
     */
    BVSet<EntId, EntIdUniverse> DecodeEntIdSet(gpg::BinaryReader& reader);
    /**
     * Address: 0x006E5010 (FUN_006E5010)
     */
    void DecodeCommandData(gpg::BinaryReader& reader, const char* decodeContext, SSTICommandIssueData& outData);
    /**
     * Address: 0x006E54B0 (FUN_006E54B0)
     */
    SSTITarget DecodeTarget(gpg::BinaryReader& reader, const char* decodeContext);
    /**
     * Address: 0x006E55C0 (FUN_006E55C0)
     */
    void DecodeCells(gpg::BinaryReader& reader, gpg::core::FastVector<SOCellPos>& cells);

    /**
     * Address: 0x004A92A0 (FUN_004A92A0, func_StringSetFilename)
     *
     * What it does:
     * Lowercases and slash-normalizes blueprint/resource identifiers.
     */
    static void NormalizeFilenameLowerSlash(msvc8::string& inOut);

    /**
     * Address: <synthetic host-build helper>
     *
     * What it does:
     * Decodes one LuaObject payload from stream using decoder-owned Lua state.
     */
    void DecodeLuaObject(gpg::BinaryReader& reader, LuaPlus::LuaObject& out);

  public:
    ICommandSink* mSink = nullptr;          // +0x0C
    gpg::Stream* mStream = nullptr;         // +0x10
    RRuleGameRules* mRules = nullptr;       // +0x14
    LuaPlus::LuaState* mLuaState = nullptr; // +0x18
  };

  static_assert(offsetof(CDecoder, mSink) == 0x0C, "CDecoder::mSink offset must be 0x0C");
  static_assert(offsetof(CDecoder, mStream) == 0x10, "CDecoder::mStream offset must be 0x10");
  static_assert(offsetof(CDecoder, mRules) == 0x14, "CDecoder::mRules offset must be 0x14");
  static_assert(offsetof(CDecoder, mLuaState) == 0x18, "CDecoder::mLuaState offset must be 0x18");
  static_assert(sizeof(CDecoder) == 0x1C, "CDecoder size must be 0x1C");
} // namespace moho
