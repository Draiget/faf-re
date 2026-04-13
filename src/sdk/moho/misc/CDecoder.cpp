#include "CDecoder.h"

#include <cstring>
#include <stdexcept>

#include "gpg/core/algorithms/MD5.h"
#include "gpg/core/containers/String.h"
#include "lua/LuaObject.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/net/CMessage.h"
#include "moho/net/CMessageStream.h"
#include "moho/net/ECmdStreamOp.h"
#include "moho/render/camera/VTransform.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/resource/RResId.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SOCellPos.h"

namespace
{
  class XDecoderMessageError final : public std::runtime_error
  {
  public:
    explicit XDecoderMessageError(const char* message)
      : std::runtime_error(message ? message : "Decoder message error")
    {}
  };

  constexpr std::uint32_t kNoTargetEntityId = 0xF0000000u;

  [[noreturn]] void ThrowDecoderError(const msvc8::string& message)
  {
    throw XDecoderMessageError(message.c_str());
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x006E4060 (FUN_006E4060)
   * Mangled:
   * ??0CDecoder@Moho@@QAE@PAVICommandSink@1@AAV?$auto_ptr@VStream@gpg@@@std@@PAVRRuleGameRules@1@PAVLuaState@LuaPlus@@@Z
   *
   * What it does:
   * Initializes receiver links, steals optional stream ownership, and stores
   * sink/rules/lua decode dependencies.
   */
  CDecoder::CDecoder(
    msvc8::auto_ptr<gpg::Stream>& stream, ICommandSink* sink, RRuleGameRules* rules, LuaPlus::LuaState* luaState
  )
    : IMessageReceiver()
    , mSink(sink)
    , mStream(stream.release())
    , mRules(rules)
    , mLuaState(luaState)
  {}

  /**
   * Address: 0x006E40A0 (FUN_006E40A0)
   * Mangled: ??1CDecoder@Moho@@QAE@XZ
   *
   * What it does:
   * Releases owned decode stream and unlinks receiver attachments.
   */
  CDecoder::~CDecoder()
  {
    delete mStream;
    mStream = nullptr;
  }

  /**
   * Address: 0x006E40F0 (FUN_006E40F0)
   * Mangled: ?ProcessMessage@CDecoder@Moho@@UAEXABVCMessage@2@PAVCMessageDispatcher@2@@Z
   *
   * What it does:
   * Appends incoming wire bytes into owned stream (if present) and dispatches
   * decode by opcode.
   */
  void CDecoder::ReceiveMessage(CMessage* message, CMessageDispatcher* dispatcher)
  {
    (void)dispatcher;

    if (mStream && message && message->mBuff.start_) {
      const char* const begin = message->mBuff.start_;
      const char* const end = message->mBuff.end_;
      const std::size_t size = static_cast<std::size_t>(end - begin);

      if (size <= mStream->LeftToWrite()) {
        std::memcpy(mStream->mWriteHead, begin, size);
        mStream->mWriteHead += size;
      } else {
        mStream->VirtWrite(begin, size);
      }
    }

    DecodeMessage(*message);
  }

  /**
   * Address: 0x006E4150 (FUN_006E4150 thunk) -> 0x0128F810 (FUN_0128F810)
   *
   * What it does:
   * Builds a read-only message stream view and dispatches command-opcode decode.
   */
  void CDecoder::DecodeMessage(const CMessage& message)
  {
    CMessageStream stream(const_cast<CMessage*>(&message), CMessageStream::Access::kReadOnly);
    gpg::BinaryReader reader(&stream);

    const auto opcode = static_cast<ECmdStreamOp>(static_cast<std::uint8_t>(message.mBuff[0]));

    switch (opcode) {
    case ECmdStreamOp::CMDST_Advance:
      DecodeAdvance(reader);
      return;
    case ECmdStreamOp::CMDST_SetCommandSource:
      DecodeSetCommandSource(reader);
      return;
    case ECmdStreamOp::CMDST_CommandSourceTerminated:
      mSink->OnCommandSourceTerminated();
      return;
    case ECmdStreamOp::CMDST_VerifyChecksum:
      DecodeVerifyChecksum(reader);
      return;
    case ECmdStreamOp::CMDST_RequestPause:
      mSink->RequestPause();
      return;
    case ECmdStreamOp::CMDST_Resume:
      mSink->Resume();
      return;
    case ECmdStreamOp::CMDST_SingleStep:
      mSink->SingleStep();
      return;
    case ECmdStreamOp::CMDST_CreateUnit:
      DecodeCreateUnit(reader);
      return;
    case ECmdStreamOp::CMDST_CreateProp:
      DecodeCreateProp(reader);
      return;
    case ECmdStreamOp::CMDST_DestroyEntity:
      DecodeDestroyEntity(reader);
      return;
    case ECmdStreamOp::CMDST_WarpEntity:
      DecodeWarpEntity(reader);
      return;
    case ECmdStreamOp::CMDST_ProcessInfoPair:
      DecodeProcessInfoPair(reader);
      return;
    case ECmdStreamOp::CMDST_IssueCommand:
      DecodeIssueCommand(reader);
      return;
    case ECmdStreamOp::CMDST_IssueFactoryCommand:
      DecodeIssueFactoryCommand(reader);
      return;
    case ECmdStreamOp::CMDST_IncreaseCommandCount:
      DecodeIncreaseCommandCount(reader);
      return;
    case ECmdStreamOp::CMDST_DecreaseCommandCount:
      DecodeDecreaseCommandCount(reader);
      return;
    case ECmdStreamOp::CMDST_SetCommandTarget:
      DecodeSetCommandTarget(reader);
      return;
    case ECmdStreamOp::CMDST_SetCommandType:
      DecodeSetCommandType(reader);
      return;
    case ECmdStreamOp::CMDST_SetCommandCells:
      DecodeSetCommandCells(reader);
      return;
    case ECmdStreamOp::CMDST_RemoveCommandFromQueue:
      DecodeRemoveCommandFromQueue(reader);
      return;
    case ECmdStreamOp::CMDST_DebugCommand:
      DecodeDebugCommand(reader);
      return;
    case ECmdStreamOp::CMDST_ExecuteLuaInSim:
      DecodeExecuteLuaInSim(reader);
      return;
    case ECmdStreamOp::CMDST_LuaSimCallback:
      DecodeLuaSimCallback(reader);
      return;
    case ECmdStreamOp::CMDST_EndGame:
      DecodeEndGame();
      return;
    default:
      break;
    }

    ThrowDecoderError(
      gpg::STR_Printf("Unexpected opcode in command stream: 0x%02x", static_cast<std::uint8_t>(opcode))
    );
  }

  /**
   * Address: 0x006E4400 (FUN_006E4400)
   */
  void CDecoder::DecodeAdvance(gpg::BinaryReader& reader)
  {
    if (mStream) {
      mStream->VirtFlush();
    }

    std::int32_t beats = 0;
    reader.ReadExact(beats);
    mSink->AdvanceBeat(beats);
  }

  /**
   * Address: 0x0128CC00 (FUN_0128CC00, Moho__CDecoder__DecodeMessage)
   *
   * What it does:
   * Builds a read-only message stream view and dispatches only
   * `CMDST_Advance` / `CMDST_SetCommandSource`; all other opcodes throw.
   */
  void CDecoder::DecodeMessagePatched(const CMessage& message)
  {
    CMessageStream stream(const_cast<CMessage*>(&message), CMessageStream::Access::kReadOnly);
    gpg::BinaryReader reader(&stream);

    const auto opcode = static_cast<ECmdStreamOp>(static_cast<std::uint8_t>(message.mBuff[0]));
    switch (opcode) {
    case ECmdStreamOp::CMDST_Advance:
      DecodeAdvance(reader);
      return;
    case ECmdStreamOp::CMDST_SetCommandSource:
      DecodeSetCommandSource(reader);
      return;
    default:
      break;
    }

    ThrowDecoderError(
      gpg::STR_Printf("Unexpected opcode in command stream: 0x%02x", static_cast<std::uint8_t>(opcode))
    );
  }

  /**
   * Address: 0x006E4440 (FUN_006E4440)
   */
  void CDecoder::DecodeSetCommandSource(gpg::BinaryReader& reader)
  {
    std::uint8_t source = 0;
    reader.ReadExact(source);
    mSink->SetCommandSource(static_cast<CommandSourceId>(source));
  }

  /**
   * Address: 0x006E4480 (FUN_006E4480)
   */
  void CDecoder::DecodeVerifyChecksum(gpg::BinaryReader& reader)
  {
    gpg::MD5Digest digest{};
    CSeqNo beat = 0;
    reader.ReadExact(digest);
    reader.ReadExact(beat);
    mSink->VerifyChecksum(digest, beat);
  }

  /**
   * Address: 0x006E44F0 (FUN_006E44F0)
   */
  void CDecoder::DecodeCreateUnit(gpg::BinaryReader& reader)
  {
    std::uint8_t armyIndex = 0;
    msvc8::string blueprintId;
    SCoordsVec2 pos{};
    float heading = 0.0f;

    reader.ReadExact(armyIndex);
    reader.ReadString(&blueprintId);
    reader.ReadExact(pos);
    reader.ReadExact(heading);

    RResId resId{};
    resId.name = blueprintId;
    NormalizeFilenameLowerSlash(resId.name);

    mSink->CreateUnit(static_cast<std::uint32_t>(armyIndex), resId, pos, heading);
  }

  /**
   * Address: 0x006E45D0 (FUN_006E45D0)
   */
  void CDecoder::DecodeCreateProp(gpg::BinaryReader& reader)
  {
    msvc8::string blueprintPath;
    Wm3::Vec3f location{};
    reader.ReadString(&blueprintPath);
    reader.ReadExact(location);
    mSink->CreateProp(blueprintPath.c_str(), location);
  }

  /**
   * Address: 0x006E4670 (FUN_006E4670)
   */
  void CDecoder::DecodeDestroyEntity(gpg::BinaryReader& reader)
  {
    EntId entityId = 0;
    reader.ReadExact(entityId);
    mSink->DestroyEntity(entityId);
  }

  /**
   * Address: 0x006E46A0 (FUN_006E46A0)
   */
  void CDecoder::DecodeWarpEntity(gpg::BinaryReader& reader)
  {
    EntId entityId = 0;
    VTransform transform{};
    reader.ReadExact(entityId);
    reader.ReadExact(transform);
    mSink->WarpEntity(entityId, transform);
  }

  /**
   * Address: 0x006E46E0 (FUN_006E46E0)
   */
  void CDecoder::DecodeProcessInfoPair(gpg::BinaryReader& reader)
  {
    EntId entityId = 0;
    msvc8::string key;
    msvc8::string value;

    reader.ReadExact(entityId);
    reader.ReadString(&key);
    reader.ReadString(&value);

    mSink->ProcessInfoPair(reinterpret_cast<void*>(static_cast<std::uintptr_t>(entityId)), key.c_str(), value.c_str());
  }

  /**
   * Address: 0x006E47D0 (FUN_006E47D0)
   */
  void CDecoder::DecodeIssueCommand(gpg::BinaryReader& reader)
  {
    const BVSet<EntId, EntIdUniverse> entities = DecodeEntIdSet(reader);
    SSTICommandIssueData commandData(EUnitCommandType::UNITCOMMAND_None);
    DecodeCommandData(reader, "CDecoder::DecodeIssueCommand()", commandData);

    std::uint8_t clearQueue = 0;
    reader.ReadExact(clearQueue);
    if (clearQueue >= 2u) {
      ThrowDecoderError(
        gpg::STR_Printf(
          "Invalid value for ClearQueue flag in CDecoder::DecodeIssueCommand(): %d", static_cast<int>(clearQueue)
        )
      );
    }

    mSink->IssueCommand(entities, commandData, clearQueue != 0);
  }

  /**
   * Address: 0x006E48E0 (FUN_006E48E0)
   */
  void CDecoder::DecodeIssueFactoryCommand(gpg::BinaryReader& reader)
  {
    const BVSet<EntId, EntIdUniverse> entities = DecodeEntIdSet(reader);
    SSTICommandIssueData commandData(EUnitCommandType::UNITCOMMAND_None);
    DecodeCommandData(reader, "CDecoder::DecodeIssueFactoryCommand()", commandData);

    std::uint8_t clearQueue = 0;
    reader.ReadExact(clearQueue);
    if (clearQueue >= 2u) {
      ThrowDecoderError(
        gpg::STR_Printf(
          "Invalid value for ClearQueue flag in CDecoder::DecodeIssueCommand(): %d", static_cast<int>(clearQueue)
        )
      );
    }

    mSink->IssueFactoryCommand(entities, commandData, clearQueue != 0);
  }

  /**
   * Address: 0x006E49F0 (FUN_006E49F0)
   */
  void CDecoder::DecodeIncreaseCommandCount(gpg::BinaryReader& reader)
  {
    CmdId commandId = 0;
    int count = 0;
    reader.ReadExact(commandId);
    reader.ReadExact(count);
    mSink->IncreaseCommandCount(commandId, count);
  }

  /**
   * Address: 0x006E4A30 (FUN_006E4A30)
   */
  void CDecoder::DecodeDecreaseCommandCount(gpg::BinaryReader& reader)
  {
    CmdId commandId = 0;
    int count = 0;
    reader.ReadExact(commandId);
    reader.ReadExact(count);
    mSink->DecreaseCommandCount(commandId, count);
  }

  /**
   * Address: 0x006E4A70 (FUN_006E4A70)
   */
  void CDecoder::DecodeSetCommandTarget(gpg::BinaryReader& reader)
  {
    CmdId commandId = 0;
    reader.ReadExact(commandId);

    const SSTITarget target = DecodeTarget(reader, "CDecoder::DecodeSetCommandTarget()");
    mSink->SetCommandTarget(commandId, target);
  }

  /**
   * Address: 0x006E4AC0 (FUN_006E4AC0)
   */
  void CDecoder::DecodeSetCommandType(gpg::BinaryReader& reader)
  {
    CmdId commandId = 0;
    std::int32_t commandType = 0;
    reader.ReadExact(commandId);
    reader.ReadExact(commandType);
    mSink->SetCommandType(commandId, static_cast<EUnitCommandType>(commandType));
  }

  /**
   * Address: 0x006E4B00 (FUN_006E4B00)
   */
  void CDecoder::DecodeSetCommandCells(gpg::BinaryReader& reader)
  {
    CmdId commandId = 0;
    gpg::core::FastVector<SOCellPos> cells{};
    Wm3::Vec3f targetPosition{};

    reader.ReadExact(commandId);
    DecodeCells(reader, cells);
    reader.ReadExact(targetPosition);

    mSink->SetCommandCells(commandId, cells, targetPosition);
  }

  /**
   * Address: 0x006E4BB0 (FUN_006E4BB0)
   */
  void CDecoder::DecodeRemoveCommandFromQueue(gpg::BinaryReader& reader)
  {
    CmdId commandId = 0;
    EntId unitId = 0;
    reader.ReadExact(commandId);
    reader.ReadExact(unitId);
    mSink->RemoveCommandFromUnitQueue(commandId, unitId);
  }

  /**
   * Address: 0x006E4BF0 (FUN_006E4BF0)
   */
  void CDecoder::DecodeExecuteLuaInSim(gpg::BinaryReader& reader)
  {
    msvc8::string functionName;
    LuaPlus::LuaObject args;
    reader.ReadString(&functionName);
    DecodeLuaObject(reader, args);
    mSink->ExecuteLuaInSim(functionName.c_str(), args);
  }

  /**
   * Address: 0x006E4CA0 (FUN_006E4CA0)
   */
  void CDecoder::DecodeLuaSimCallback(gpg::BinaryReader& reader)
  {
    msvc8::string callbackName;
    LuaPlus::LuaObject args;
    reader.ReadString(&callbackName);
    DecodeLuaObject(reader, args);
    const BVSet<EntId, EntIdUniverse> entities = DecodeEntIdSet(reader);
    mSink->LuaSimCallback(callbackName.c_str(), args, entities);
  }

  /**
   * Address: 0x006E4D80 (FUN_006E4D80)
   */
  void CDecoder::DecodeDebugCommand(gpg::BinaryReader& reader)
  {
    msvc8::string command;
    Wm3::Vec3f worldPos{};
    std::uint8_t focusArmy = 0;

    reader.ReadString(&command);
    reader.ReadExact(worldPos);
    reader.ReadExact(focusArmy);

    const BVSet<EntId, EntIdUniverse> entities = DecodeEntIdSet(reader);
    mSink->ExecuteDebugCommand(command.c_str(), worldPos, static_cast<std::uint32_t>(focusArmy), entities);
  }

  /**
   * Address: 0x006E4E70 (FUN_006E4E70)
   */
  void CDecoder::DecodeEndGame()
  {
    delete mStream;
    mStream = nullptr;
    mSink->EndGame();
  }

  /**
   * Address: 0x006E4E90 (FUN_006E4E90 / FUN_006E4F30 / FUN_006E4FC0)
   */
  BVSet<EntId, EntIdUniverse> CDecoder::DecodeEntIdSet(gpg::BinaryReader& reader)
  {
    BVSet<EntId, EntIdUniverse> entities{};
    std::int32_t count = 0;
    reader.ReadExact(count);

    if (count == 0) {
      return entities;
    }

    gpg::core::FastVectorN<EntId, 4> rawIds{};
    rawIds.Resize(static_cast<std::size_t>(count));
    reader.Read(reinterpret_cast<char*>(rawIds.start_), static_cast<std::size_t>(count) * sizeof(EntId));

    const auto firstType = static_cast<unsigned int>(rawIds[0]) >> 28;
    for (std::int32_t i = 0; i < count; ++i) {
      const auto entityId = static_cast<unsigned int>(rawIds[static_cast<std::size_t>(i)]);
      const auto entityType = entityId >> 28;
      if (entityType != firstType) {
        ThrowDecoderError(
          gpg::STR_Printf(
            "Attempt to construct EntIdSet with different types of IDs (%d and %d) in DecodeEntIdSet",
            static_cast<int>(firstType),
            static_cast<int>(entityType)
          )
        );
      }

      entities.Bits().Add(entityId);
    }

    return entities;
  }

  /**
   * Address: 0x006E5010 (FUN_006E5010)
   */
  void
  CDecoder::DecodeCommandData(gpg::BinaryReader& reader, const char* decodeContext, SSTICommandIssueData& commandData)
  {
    commandData.mCommandType = EUnitCommandType::UNITCOMMAND_None;
    commandData.mLuaState = mLuaState ? mLuaState->GetCState() : nullptr;

    reader.ReadExact(commandData.nextCommandId);
    reader.ReadExact(commandData.unk04);

    std::uint8_t commandType = 0;
    reader.ReadExact(commandType);
    if (commandType >= 0x28u) {
      ThrowDecoderError(
        gpg::STR_Printf("Invalid command type in %s/DecodeCommandData()", decodeContext ? decodeContext : "")
      );
    }
    commandData.mCommandType = static_cast<EUnitCommandType>(commandType);

    reader.ReadExact(commandData.mIndex);

    const msvc8::string targetContext = msvc8::string(decodeContext ? decodeContext : "") + "/DecodeCommandData()";
    commandData.mTarget = DecodeTarget(reader, targetContext.c_str());
    commandData.mTarget2 = DecodeTarget(reader, targetContext.c_str());

    reader.ReadExact(commandData.unk38);
    if (commandData.unk38 != -1) {
      reader.ReadExact(commandData.mOri);
      reader.ReadExact(commandData.unk4C);
    }

    msvc8::string blueprintId;
    reader.ReadString(&blueprintId);
    if (!blueprintId.empty()) {
      RResId lookupId{};
      lookupId.name = blueprintId;
      NormalizeFilenameLowerSlash(lookupId.name);

      commandData.mBlueprint = mRules ? static_cast<RUnitBlueprint*>(mRules->GetEntityBlueprint(lookupId)) : nullptr;
      if (!commandData.mBlueprint) {
        ThrowDecoderError(gpg::STR_Printf("Invalid blueprint ID in %s", targetContext.c_str()));
      }
    } else {
      commandData.mBlueprint = nullptr;
    }

    DecodeCells(reader, commandData.mCells);
    reader.ReadExact(commandData.unk70);
    reader.ReadExact(commandData.unk74);
    DecodeLuaObject(reader, commandData.mObject);
  }

  /**
   * Address: 0x006E54B0 (FUN_006E54B0)
   */
  SSTITarget CDecoder::DecodeTarget(gpg::BinaryReader& reader, const char* decodeContext)
  {
    std::uint8_t targetType = 0;
    reader.ReadExact(targetType);

    SSTITarget target{};
    target.mEntityId = kNoTargetEntityId;
    target.mPos = Wm3::Vec3f(0.0f, 0.0f, 0.0f);

    switch (targetType) {
    case 0:
      target.mType = EAiTargetType::AITARGET_None;
      return target;
    case 1:
      target.mType = EAiTargetType::AITARGET_Entity;
      reader.ReadExact(target.mEntityId);
      return target;
    case 2:
      target.mType = EAiTargetType::AITARGET_Ground;
      reader.ReadExact(target.mPos);
      return target;
    default:
      break;
    }

    ThrowDecoderError(gpg::STR_Printf("Invalid target type in %s/DecodeTarget()", decodeContext ? decodeContext : ""));
  }

  /**
   * Address: 0x006E55C0 (FUN_006E55C0)
   */
  void CDecoder::DecodeCells(gpg::BinaryReader& reader, gpg::core::FastVector<SOCellPos>& cells)
  {
    std::int32_t count = 0;
    reader.ReadExact(count);

    delete[] cells.start_;
    cells.start_ = nullptr;
    cells.end_ = nullptr;
    cells.capacity_ = nullptr;

    if (count != 0) {
      const auto cellCount = static_cast<std::size_t>(count);
      cells.start_ = new SOCellPos[cellCount];
      cells.end_ = cells.start_ + cellCount;
      cells.capacity_ = cells.end_;
      reader.Read(reinterpret_cast<char*>(cells.start_), cellCount * sizeof(SOCellPos));
    }
  }

  /**
   * Address: 0x004A92A0 (FUN_004A92A0, func_StringSetFilename)
   *
   * What it does:
   * Lowercases and slash-normalizes blueprint/resource identifiers.
   */
  void CDecoder::NormalizeFilenameLowerSlash(msvc8::string& inOut)
  {
    gpg::STR_NormalizeFilenameLowerSlash(inOut);
  }

  /**
   * Address: <synthetic host-build helper>
   *
   * What it does:
   * Decodes one LuaObject payload from stream using decoder-owned Lua state.
   */
  void CDecoder::DecodeLuaObject(gpg::BinaryReader& reader, LuaPlus::LuaObject& out)
  {
    out.SCR_FromByteStream(out, mLuaState, &reader);
  }
} // namespace moho
