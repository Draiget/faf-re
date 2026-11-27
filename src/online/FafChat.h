#pragma once
// Engine addition (in-game launcher): FAF's chat, as FAF's clients speak it (FAForeverRustClient irc.rs, the Java
// client's KittehChatService): IRC over a WebSocket to chat.faforever.com with the binary.ircv3.net subprotocol, one
// IRC line per binary frame without its CRLF. Signed in with SASL PLAIN, the password "token:<token>" from FAF's user
// service (GET <user service>/irc/ergochat/token with the player's FAF sign-in). Joins its channels (#aeolus and the
// ones asked for), reads each one's recent history (draft/chathistory), and keeps the lines per channel.
#include <atomic>
#include <cstddef>
#include <deque>
#include <expected>
#include <functional>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "platform/Http.h"

namespace faf::online
{
  struct FafChatSettings
  {
    std::string webSocketUrl = "wss://chat.faforever.com";
    std::string userAgent = "faf-re-client";
    std::vector<std::string> channels{"#aeolus"};
    /** How many lines of each channel's history to ask for, and to keep. */
    std::size_t historyLines = 200;
    std::size_t keepLines = 1000;
  };

  /** One line of a channel: someone's message, an action ("/me"), or what happened (joined, left, a notice). */
  struct FafChatLine
  {
    std::string from;
    std::string text;
    std::string time; ///< the server's time (server-time tag, ISO), or empty
    bool self = false;
    bool action = false;
    bool event = false; ///< joined, left, topic, a notice: not a message
    bool history = false;
  };

  class FafChat
  {
  public:
    enum class State
    {
      Off,
      Connecting,
      Joined, ///< signed in, in its channels
      Failed,
    };

    /** The chat's token ("<value>" of the user service's answer); asked on the chat's own thread. */
    using TokenSource = std::function<std::expected<std::string, std::string>()>;

    explicit FafChat(FafChatSettings settings = {});
    ~FafChat();
    FafChat(const FafChat&) = delete;
    FafChat& operator=(const FafChat&) = delete;

    /** Where lines for a log go ("chat: ..."); never a token. */
    void SetLog(std::function<void(const char*)> log);
    /** Signs in as `nick` on a thread of its own; GetState says how it goes. */
    void Connect(TokenSource token, std::string nick);
    void Disconnect();

    [[nodiscard]] State GetState() const noexcept
    {
      return mState.load();
    }
    [[nodiscard]] std::string Message() const;
    /** The nick in use (with "_" added when the wanted one was taken). */
    [[nodiscard]] std::string Nick() const;
    /** The channels joined, in the order they were joined. */
    [[nodiscard]] std::vector<std::string> Channels() const;
    /** A channel's lines from `from` on (0: its first kept line); `total` the number of lines it ever had. */
    [[nodiscard]] std::vector<FafChatLine>
    Lines(const std::string& channel, std::size_t from, std::size_t& total) const;
    /** Who is in a channel (prefixes such as @ kept), sorted. */
    [[nodiscard]] std::vector<std::string> Users(const std::string& channel) const;
    /** The channel's topic, or empty. */
    [[nodiscard]] std::string Topic(const std::string& channel) const;

    /** Says `text` in a channel ("/me x" as an action). False with why when not signed in or empty. */
    std::expected<void, std::string> Say(const std::string& channel, const std::string& text);
    std::expected<void, std::string> Join(const std::string& channel);
    std::expected<void, std::string> Part(const std::string& channel);

    /** One IRC line taken apart: tags, the sender's nick, the command and its parameters (the trailing one last). */
    struct IrcMessage
    {
      std::map<std::string, std::string> tags;
      std::string nick;
      std::string command;
      std::vector<std::string> params;
    };
    [[nodiscard]] static IrcMessage Parse(const std::string& line);

  private:
    struct Channel
    {
      std::deque<FafChatLine> lines;
      std::size_t dropped = 0; ///< lines dropped from the front (Lines counts from the first line it ever had)
      std::set<std::string> users;
      std::string topic;
      bool joined = false;
    };

    void Run(TokenSource token, std::string nick);
    void Handle(const IrcMessage& message);
    void Add(const std::string& channel, FafChatLine line);
    std::expected<void, std::string> SendLine(const std::string& line);
    void Fail(std::string why);
    void Log(const std::string& text) const;

    FafChatSettings mSettings;
    std::function<void(const char*)> mLog;
    platform::http::WebSocket mSocket;
    std::mutex mSendLock;
    mutable std::mutex mLock;
    std::thread mThread;
    std::atomic<bool> mStop{false};
    std::atomic<State> mState{State::Off};
    std::string mMessage;
    std::string mNick;
    std::string mWantedNick;
    std::string mToken; ///< only while signing in (cleared after SASL)
    std::set<std::string> mCaps;
    std::vector<std::string> mOrder;          ///< channels in the order they were joined
    std::map<std::string, Channel> mChannels; ///< by lower-case name
  };
} // namespace faf::online
