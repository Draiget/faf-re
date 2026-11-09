#include "LobbyPeerFeatures.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <random>
#include <system_error>

#include <Windows.h>

#include <Windows.h>

#include <Windows.h>

#include "CLobby.h"
#include "CMessage.h"
#include "CMessageStream.h"
#include "ELobbyMsg.h"
#include "gpg/core/utils/Logging.h"
#include "INetConnection.h"
#include "lua/LuaObject.h"
#include "moho/misc/StartupHelpers.h"
#include "NetConVars.h"
#include "SPeer.h"

using namespace moho;
using namespace faf::remote::net;

namespace
{
  // First payload byte of `LOBMSG_PeerFeatures`; 0 is the announcement.
  constexpr std::uint8_t kKindChallenge = 1;
  constexpr std::uint8_t kKindProof = 2;

  constexpr std::size_t kChallengeBytes = 1u + sizeof(StyleChallenge);
  constexpr std::size_t kProofBytes = 1u + sizeof(StyleColor) + sizeof(StyleSignature);

  // Checks every style. The matching private key is not in this repository.
  constexpr StylePublicKey kStylePublicKey = {
    0xa4, 0x97, 0xd0, 0xa2, 0x6d, 0xc4, 0xbb, 0x65,
    0x84, 0xa9, 0xbe, 0x14, 0xb2, 0x95, 0x61, 0xf0,
    0x40, 0x01, 0x85, 0x39, 0xaa, 0x5c, 0x26, 0xb3,
    0x54, 0xe2, 0x2c, 0xc8, 0x66, 0xfd, 0xad, 0x58,
  };

  [[nodiscard]] int HexDigit(const char c) noexcept
  {
    if (c >= '0' && c <= '9') {
      return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
      return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
      return c - 'A' + 10;
    }
    return -1;
  }

  template <std::size_t N>
  [[nodiscard]] bool ParseHex(const std::string& text, std::array<std::uint8_t, N>& out) noexcept
  {
    if (text.size() != N * 2u) {
      return false;
    }
    for (std::size_t i = 0; i < N; ++i) {
      const int high = HexDigit(text[i * 2u]);
      const int low = HexDigit(text[i * 2u + 1u]);
      if (high < 0 || low < 0) {
        return false;
      }
      out[i] = static_cast<std::uint8_t>(high * 16 + low);
    }
    return true;
  }

  [[nodiscard]] std::string FormatColor(const StyleColor& color)
  {
    char text[7];
    std::snprintf(text, sizeof(text), "%02x%02x%02x", color[0], color[1], color[2]);
    return text;
  }

  // /peerstylekey <file>, otherwise peer_style.key beside the exe.
  [[nodiscard]] std::filesystem::path KeyFilePath()
  {
    fa::vector<fa::string> args;
    if (CFG_GetArgOption("/peerstylekey", 1u, &args) && !args.empty()) {
      return std::filesystem::path(args[0].c_str());
    }
    std::array<wchar_t, MAX_PATH> modulePath{};
    const DWORD length = ::GetModuleFileNameW(nullptr, modulePath.data(), static_cast<DWORD>(modulePath.size()));
    if (length == 0U || length >= modulePath.size()) {
      return {};
    }
    return std::filesystem::path(modulePath.data()).parent_path() / L"peer_style.key";
  }

  // The lobby the wrapped SetSlotInfo below asks. One exists at a time; a rehost
  // installs the next one before the old one goes.
  const CLobbyPeerFeatures* sSlotStyles = nullptr;

  void PushField(lua_State* const state, const int tableIndex, const char* const name)
  {
    // Relative to the top before the push; the globals table's index is absolute.
    const int table = tableIndex < 0 && tableIndex != LUA_GLOBALSINDEX ? lua_gettop(state) + tableIndex + 1 : tableIndex;
    lua_pushstring(state, name);
    lua_gettable(state, table);
  }

  // Pushes the lobby script's module table, or returns false with nothing pushed.
  // Looked up, not imported: autolobby games never load that script.
  [[nodiscard]] bool PushLobbyModule(lua_State* const state)
  {
    PushField(state, LUA_GLOBALSINDEX, "__modules");
    if (lua_type(state, -1) != LUA_TTABLE) {
      lua_pop(state, 1);
      return false;
    }
    PushField(state, -1, "/lua/ui/lobby/lobby.lua");
    lua_remove(state, -2);
    if (lua_type(state, -1) != LUA_TTABLE) {
      lua_pop(state, 1);
      return false;
    }
    return true;
  }

  // Pushes the script's file-local GUI, an upvalue of its SetSlotInfo (the function
  // at the absolute or upvalue index `function`, or the one wrapped by it). False with
  // nothing pushed if not found.
  [[nodiscard]] bool PushLobbyGui(lua_State* const state, const int function)
  {
    const int top = lua_gettop(state);
    int script = function;
    if (lua_type(state, script) == LUA_CFUNCTION) {
      if (lua_getupvalue(state, script, 1) == nullptr) {
        return false;
      }
      script = lua_gettop(state);
    }
    for (int index = 1;; ++index) {
      const char* const name = lua_getupvalue(state, script, index);
      if (name == nullptr) {
        lua_settop(state, top);
        return false;
      }
      if (std::strcmp(name, "GUI") == 0) {
        // Over the wrapped function, when that was pushed first.
        if (lua_gettop(state) > top + 1) {
          lua_replace(state, top + 1);
        }
        return true;
      }
      lua_pop(state, 1);
    }
  }

  // GUI.slots[slot].name:SetTitleTextColor(style). A failure costs the colour only.
  void PaintSlot(lua_State* const state, const int function, const double slot, const std::string& style)
  {
    const int top = lua_gettop(state);
    if (PushLobbyGui(state, function) && lua_type(state, -1) == LUA_TTABLE) {
      PushField(state, -1, "slots");
      if (lua_type(state, -1) == LUA_TTABLE) {
        lua_pushnumber(state, slot);
        lua_gettable(state, -2);
        if (lua_type(state, -1) == LUA_TTABLE) {
          PushField(state, -1, "name");
          if (lua_type(state, -1) == LUA_TTABLE) {
            PushField(state, -1, "SetTitleTextColor");
            lua_pushvalue(state, -2);
            lua_pushstring(state, style.c_str());
            if (LuaCallProtected(state, 2, 0) != 0) {
              gpg::Warnf("PEERS: could not show a style on slot %d", static_cast<int>(slot));
            }
          }
        }
      }
    }
    lua_settop(state, top);
  }

  // Stands in for the lobby script's SetSlotInfo(slotNum, playerInfo): the script's
  // function is upvalue 1. It sets the name's colour by the slot's state, so a style
  // goes on after it, over the host, player and local colours.
  int SetSlotInfoWithStyle(lua_State* const state)
  {
    const int argumentCount = lua_gettop(state);
    lua_pushvalue(state, lua_upvalueindex(1));
    for (int index = 1; index <= argumentCount; ++index) {
      lua_pushvalue(state, index);
    }
    lua_call(state, argumentCount, 0);

    if (sSlotStyles == nullptr || argumentCount < 2 || lua_type(state, 2) != LUA_TTABLE) {
      return 0;
    }
    PushField(state, 2, "Human");
    const bool human = lua_toboolean(state, -1) != 0;
    lua_pop(state, 1);
    if (!human) {
      return 0;
    }
    PushField(state, 2, "OwnerID");
    const char* const owner = lua_tostring(state, -1);
    const std::string style = owner != nullptr ? sSlotStyles->StyleOf(std::atoi(owner)) : std::string{};
    lua_pop(state, 1);
    if (!style.empty()) {
      PaintSlot(state, lua_upvalueindex(1), lua_tonumber(state, 1), style);
    }
    return 0;
  }
} // namespace

CLobbyPeerFeatures::CLobbyPeerFeatures(const CLobby& lobby)
  : mLobby(lobby)
{
  LoadKey();
}

CLobbyPeerFeatures::~CLobbyPeerFeatures()
{
  if (sSlotStyles == this) {
    sSlotStyles = nullptr;
  }
}

void CLobbyPeerFeatures::InstallSlotStyles(lua_State* const state)
{
  sSlotStyles = this;

  const int top = lua_gettop(state);
  if (PushLobbyModule(state)) {
    PushField(state, -1, "SetSlotInfo");
    // LUA_TFUNCTION is a script function in this fork; a C function here has its own
    // type, and is the wrapper already, from the lobby before this one.
    if (lua_type(state, -1) == LUA_TFUNCTION) {
      lua_pushstring(state, "SetSlotInfo");
      lua_pushvalue(state, -2);
      lua_pushcclosure(state, &SetSlotInfoWithStyle, 1);
      lua_settable(state, -4);
    }
  }
  lua_settop(state, top);
}

void CLobbyPeerFeatures::PaintPeer(lua_State* const state, const std::int32_t uid) const
{
  const std::string style = StyleOf(uid);
  const int top = lua_gettop(state);
  if (!style.empty() && PushLobbyModule(state)) {
    const int module = lua_gettop(state);
    PushField(state, module, "FindSlotForID");
    lua_pushstring(state, std::to_string(uid).c_str());
    if (LuaCallProtected(state, 1, 1) == 0 && lua_type(state, -1) == LUA_TNUMBER) {
      const double slot = lua_tonumber(state, -1);
      PushField(state, module, "SetSlotInfo");
      if (lua_type(state, -1) == LUA_CFUNCTION) {
        PaintSlot(state, lua_gettop(state), slot, style);
      }
    }
  }
  lua_settop(state, top);
}

void CLobbyPeerFeatures::LoadKey()
{
  const std::filesystem::path path = KeyFilePath();
  std::error_code error;
  if (path.empty() || !std::filesystem::is_regular_file(path, error)) {
    return;
  }

  // The seed in hex, then the colour as rrggbb.
  std::ifstream file(path);
  std::string seedText;
  std::string colorText;
  file >> seedText >> colorText;

  StyleSeed seed{};
  StyleColor color{};
  const bool parsed = ParseHex(seedText, seed) && ParseHex(colorText, color);
  seedText.assign(seedText.size(), '\0');
  if (!parsed) {
    gpg::Warnf("PEERS: style key file is malformed, no style");
    return;
  }

  auto key = std::make_unique<StyleSigningKey>();
  MakeStyleSigningKey(seed, *key);
  if (key->publicKey != kStylePublicKey) {
    gpg::Warnf("PEERS: style key is not the known key, no style");
    return;
  }
  mKey = std::move(key);
  mLocalStyle = color;
}

void CLobbyPeerFeatures::PeerEstablished(const SPeer& peer)
{
  mPeers[peer.uid] = SLobbyPeer{};

  if (net_LobbyPeerFeatures == 0 || peer.peerConnection == nullptr) {
    return;
  }

  const std::uint64_t mask = mKey != nullptr ? PeerFeatureBit(EPeerFeature::SignedStyle) : 0u;
  CMessage message(ELobbyMsg::LOBMSG_PeerFeatures);
  CMessageStream stream(message);
  WritePeerAnnouncement(stream, mask);
  peer.peerConnection->Write(message);
}

bool CLobbyPeerFeatures::Receive(const SPeer& peer, const std::int32_t localUid, CMessage& message)
{
  const auto size = static_cast<std::size_t>(message.GetMessageSize());
  const char* const payload = message.mBuff.start_ + 3;
  if (net_LobbyPeerFeatures == 0 || size == 0u || peer.peerConnection == nullptr) {
    return false;
  }

  SLobbyPeer& state = mPeers[peer.uid];
  const auto kind = static_cast<std::uint8_t>(payload[0]);

  if (kind == kPeerKindAnnounce) {
    if (state.announced || !ReadPeerAnnouncement(payload, size, state.announcement)) {
      return false;
    }
    state.announced = true;
    gpg::Logf(
      "PEERS: lobby player %d:%s runs our engine, features %016llx, build %s", peer.uid, peer.playerName.c_str(),
      static_cast<unsigned long long>(state.announcement.mask), state.announcement.build.c_str()
    );

    if ((state.announcement.mask & PeerFeatureBit(EPeerFeature::SignedStyle)) != 0u) {
      std::random_device random;
      for (std::uint8_t& byte : state.challenge) {
        byte = static_cast<std::uint8_t>(random());
      }
      state.awaitingProof = true;

      CMessage reply(ELobbyMsg::LOBMSG_PeerFeatures);
      CMessageStream stream(reply);
      stream.Write(kKindChallenge);
      stream.Write(reinterpret_cast<const char*>(state.challenge.data()), state.challenge.size());
      peer.peerConnection->Write(reply);
    }
    return false;
  }

  if (kind == kKindChallenge) {
    // One answer per link: a player can't make this client sign without limit.
    if (mKey == nullptr || !state.announced || state.challengeAnswered || size != kChallengeBytes) {
      return false;
    }
    state.challengeAnswered = true;

    StyleChallenge challenge{};
    std::memcpy(challenge.data(), payload + 1, challenge.size());
    const StyleSignature signature = SignStyle(*mKey, localUid, peer.uid, challenge, mLocalStyle);

    CMessage reply(ELobbyMsg::LOBMSG_PeerFeatures);
    CMessageStream stream(reply);
    stream.Write(kKindProof);
    stream.Write(reinterpret_cast<const char*>(mLocalStyle.data()), mLocalStyle.size());
    stream.Write(reinterpret_cast<const char*>(signature.data()), signature.size());
    peer.peerConnection->Write(reply);
    return false;
  }

  if (kind == kKindProof) {
    if (!state.awaitingProof || size != kProofBytes) {
      return false;
    }
    state.awaitingProof = false;

    StyleColor color{};
    StyleSignature signature{};
    std::memcpy(color.data(), payload + 1, color.size());
    std::memcpy(signature.data(), payload + 1 + color.size(), signature.size());
    if (!CheckStyle(kStylePublicKey, peer.uid, localUid, state.challenge, color, signature)) {
      gpg::Logf("PEERS: lobby player %d:%s gave a style proof that does not check", peer.uid, peer.playerName.c_str());
      return false;
    }
    state.hasStyle = true;
    state.style = color;
    gpg::Logf("PEERS: lobby player %d:%s has style %s", peer.uid, peer.playerName.c_str(), FormatColor(color).c_str());
    return true;
  }

  return false;
}

bool CLobbyPeerFeatures::PeerRunsOurEngine(const std::int32_t uid) const
{
  const auto found = mPeers.find(uid);
  return found != mPeers.end() && found->second.announced;
}

std::string CLobbyPeerFeatures::StyleOf(const std::int32_t uid) const
{
  if (uid == mLobby.localUid) {
    return mKey != nullptr ? FormatColor(mLocalStyle) : std::string{};
  }
  const auto found = mPeers.find(uid);
  return found != mPeers.end() && found->second.hasStyle ? FormatColor(found->second.style) : std::string{};
}
