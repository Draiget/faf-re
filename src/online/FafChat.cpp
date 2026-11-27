#include "online/FafChat.h"

#include <algorithm>
#include <cctype>
#include <utility>

namespace faf::online
{
  namespace
  {
    std::string Lower(
      std::string text
    )
    {
      for (char& c : text) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      }
      return text;
    }

    std::string Base64(
      const std::string& bytes
    )
    {
      static const char* const kAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
      std::string out;
      std::size_t i = 0;
      for (; i + 2 < bytes.size(); i += 3) {
        const unsigned v = (static_cast<unsigned char>(bytes[i]) << 16) |
          (static_cast<unsigned char>(bytes[i + 1]) << 8) | static_cast<unsigned char>(bytes[i + 2]);
        out += kAlphabet[(v >> 18) & 63];
        out += kAlphabet[(v >> 12) & 63];
        out += kAlphabet[(v >> 6) & 63];
        out += kAlphabet[v & 63];
      }
      if (i < bytes.size()) {
        unsigned v = static_cast<unsigned char>(bytes[i]) << 16;
        if (i + 1 < bytes.size()) {
          v |= static_cast<unsigned char>(bytes[i + 1]) << 8;
        }
        out += kAlphabet[(v >> 18) & 63];
        out += kAlphabet[(v >> 12) & 63];
        out += i + 1 < bytes.size() ? kAlphabet[(v >> 6) & 63] : '=';
        out += '=';
      }
      return out;
    }

    /** An IRC tag value with its escapes undone (\: ; \s space, \\ backslash). */
    std::string Unescape(
      const std::string& value
    )
    {
      std::string out;
      for (std::size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '\\' && i + 1 < value.size()) {
          const char next = value[++i];
          out += next == ':' ? ';' : (next == 's' ? ' ' : (next == 'r' ? '\r' : (next == 'n' ? '\n' : next)));
        } else {
          out += value[i];
        }
      }
      return out;
    }

    /** A channel name as IRC wants it: '#' first, no spaces or commas. Empty when nothing is left. */
    std::string ChannelName(
      std::string name
    )
    {
      name.erase(
        std::remove_if(
          name.begin(),
          name.end(),
          [](char c) {
        return c == ' ' || c == ',' || c == '\a';
      }
        ),
        name.end()
      );
      if (name.empty()) {
        return {};
      }
      if (name[0] != '#' && name[0] != '&') {
        name = "#" + name;
      }
      return name.size() > 1 ? name : std::string();
    }
  } // namespace

  FafChat::FafChat(
    FafChatSettings settings
  )
    : mSettings(std::move(settings))
  {}

  FafChat::~FafChat()
  {
    Disconnect();
  }

  void FafChat::SetLog(
    std::function<void(const char*)> log
  )
  {
    mLog = std::move(log);
  }

  void FafChat::Log(
    const std::string& text
  ) const
  {
    if (mLog) {
      mLog(("chat: " + text).c_str());
    }
  }

  void FafChat::Fail(
    std::string why
  )
  {
    Log(why);
    {
      std::lock_guard<std::mutex> lock(mLock);
      mMessage = std::move(why);
    }
    mState = State::Failed;
  }

  std::string FafChat::Message() const
  {
    std::lock_guard<std::mutex> lock(mLock);
    return mMessage;
  }

  std::string FafChat::Nick() const
  {
    std::lock_guard<std::mutex> lock(mLock);
    return mNick;
  }

  std::vector<std::string> FafChat::Channels() const
  {
    std::lock_guard<std::mutex> lock(mLock);
    std::vector<std::string> out;
    for (const std::string& name : mOrder) {
      const auto found = mChannels.find(Lower(name));
      if (found != mChannels.end() && found->second.joined) {
        out.push_back(name);
      }
    }
    return out;
  }

  std::vector<FafChatLine> FafChat::Lines(
    const std::string& channel,
    const std::size_t from,
    std::size_t& total
  ) const
  {
    std::lock_guard<std::mutex> lock(mLock);
    total = 0;
    const auto found = mChannels.find(Lower(channel));
    if (found == mChannels.end()) {
      return {};
    }
    const Channel& kept = found->second;
    total = kept.dropped + kept.lines.size();
    std::vector<FafChatLine> out;
    for (std::size_t i = std::max(from, kept.dropped); i < total; ++i) {
      out.push_back(kept.lines[i - kept.dropped]);
    }
    return out;
  }

  std::vector<std::string> FafChat::Users(
    const std::string& channel
  ) const
  {
    std::lock_guard<std::mutex> lock(mLock);
    const auto found = mChannels.find(Lower(channel));
    return found == mChannels.end() ? std::vector<std::string>{}
                                    : std::vector<std::string>(found->second.users.begin(), found->second.users.end());
  }

  std::string FafChat::Topic(
    const std::string& channel
  ) const
  {
    std::lock_guard<std::mutex> lock(mLock);
    const auto found = mChannels.find(Lower(channel));
    return found == mChannels.end() ? std::string() : found->second.topic;
  }

  void FafChat::Connect(
    TokenSource token,
    std::string nick
  )
  {
    Disconnect();
    mStop = false;
    {
      std::lock_guard<std::mutex> lock(mLock);
      mMessage.clear();
      mNick = nick;
      mWantedNick = nick;
      mCaps.clear();
    }
    mState = State::Connecting;
    mThread = std::thread([this, token = std::move(token), nick = std::move(nick)]() mutable {
      Run(std::move(token), std::move(nick));
    });
  }

  void FafChat::Disconnect()
  {
    mStop = true;
    if (mSocket.IsOpen()) {
      (void)SendLine("QUIT :leaving");
    }
    mSocket.Close();
    if (mThread.joinable()) {
      mThread.join();
    }
    std::lock_guard<std::mutex> lock(mLock);
    for (auto& [name, channel] : mChannels) {
      channel.joined = false;
      channel.users.clear();
    }
    if (mState.load() != State::Failed) {
      mState = State::Off;
    }
  }

  std::expected<void, std::string> FafChat::SendLine(
    const std::string& line
  )
  {
    std::lock_guard<std::mutex> lock(mSendLock);
    return mSocket.SendBinary(line);
  }

  FafChat::IrcMessage FafChat::Parse(
    const std::string& raw
  )
  {
    IrcMessage message;
    std::string line = raw;
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) {
      line.pop_back();
    }
    std::size_t at = 0;
    if (at < line.size() && line[at] == '@') {
      const std::size_t end = line.find(' ', at);
      const std::string tags = line.substr(at + 1, end == std::string::npos ? std::string::npos : end - at - 1);
      for (std::size_t from = 0; from <= tags.size();) {
        const std::size_t semi = tags.find(';', from);
        const std::string tag = tags.substr(from, semi == std::string::npos ? std::string::npos : semi - from);
        const std::size_t eq = tag.find('=');
        if (!tag.empty()) {
          message.tags[tag.substr(0, eq)] = eq == std::string::npos ? std::string() : Unescape(tag.substr(eq + 1));
        }
        if (semi == std::string::npos) {
          break;
        }
        from = semi + 1;
      }
      at = end == std::string::npos ? line.size() : end + 1;
    }
    while (at < line.size() && line[at] == ' ') {
      ++at;
    }
    if (at < line.size() && line[at] == ':') {
      const std::size_t end = line.find(' ', at);
      const std::string prefix = line.substr(at + 1, end == std::string::npos ? std::string::npos : end - at - 1);
      message.nick = prefix.substr(0, prefix.find_first_of("!@"));
      at = end == std::string::npos ? line.size() : end + 1;
    }
    while (at < line.size()) {
      while (at < line.size() && line[at] == ' ') {
        ++at;
      }
      if (at >= line.size()) {
        break;
      }
      if (line[at] == ':' && !message.command.empty()) {
        message.params.push_back(line.substr(at + 1));
        break;
      }
      const std::size_t end = line.find(' ', at);
      const std::string word = line.substr(at, end == std::string::npos ? std::string::npos : end - at);
      if (message.command.empty()) {
        message.command = word;
      } else {
        message.params.push_back(word);
      }
      at = end == std::string::npos ? line.size() : end;
    }
    for (char& c : message.command) {
      c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    return message;
  }

  void FafChat::Add(
    const std::string& channel,
    FafChatLine line
  )
  {
    std::lock_guard<std::mutex> lock(mLock);
    Channel& kept = mChannels[Lower(channel)];
    kept.lines.push_back(std::move(line));
    while (kept.lines.size() > mSettings.keepLines) {
      kept.lines.pop_front();
      ++kept.dropped;
    }
  }

  void FafChat::Run(
    TokenSource tokenSource,
    std::string nick
  )
  {
    const auto token = tokenSource();
    if (!token) {
      Fail("no chat sign-in: " + token.error());
      return;
    }
    if (mStop.load()) {
      return;
    }
    {
      std::lock_guard<std::mutex> lock(mLock);
      mToken = *token;
    }
    Log("connecting to " + mSettings.webSocketUrl);
    if (
      const auto opened =
        mSocket.Open(mSettings.webSocketUrl, "Sec-WebSocket-Protocol: binary.ircv3.net\r\n", mSettings.userAgent);
      !opened
    ) {
      Fail("FAF's chat didn't answer: " + opened.error());
      return;
    }
    // FAF's clients ask for these (irc.rs): SASL first, then the welcome.
    (void)SendLine("CAP LS 302");
    std::string pending;
    while (!mStop.load()) {
      std::string message;
      const auto received = mSocket.Receive(message);
      if (!received || *received == platform::http::WebSocket::Received::Closed) {
        if (!mStop.load()) {
          Fail(received ? std::string("FAF's chat closed the connection") : received.error());
        }
        break;
      }
      // One line a frame as FAF's chat sends them; lines a frame split or joined are put together here.
      pending += message;
      if (pending.find('\n') == std::string::npos) {
        pending += '\n';
      }
      for (std::size_t end; (end = pending.find('\n')) != std::string::npos;) {
        const std::string line = pending.substr(0, end);
        pending.erase(0, end + 1);
        if (line.find_first_not_of(" \r") != std::string::npos) {
          Handle(Parse(line));
        }
      }
    }
    (void)nick;
  }

  void FafChat::Handle(
    const IrcMessage& message
  )
  {
    const std::string& command = message.command;
    const auto param = [&](std::size_t index) -> std::string {
      return index < message.params.size() ? message.params[index] : std::string();
    };
    if (command == "PING") {
      (void)SendLine("PONG :" + param(0));
    } else if (command == "CAP") {
      const std::string sub = param(1);
      if (sub == "LS") {
        // The last parameter lists what the server offers ("sasl=PLAIN server-time ..."), maybe over several lines.
        std::string offered = message.params.empty() ? std::string() : message.params.back();
        std::string wanted;
        for (const char* cap : {"sasl", "server-time", "message-tags", "multi-prefix", "draft/chathistory", "batch"}) {
          const std::string name(cap);
          const std::size_t at = (" " + offered + " ").find(" " + name);
          if (at != std::string::npos) {
            wanted += (wanted.empty() ? "" : " ") + name;
          }
        }
        if (param(2) != "*") { // the last line of the list
          (void)SendLine("CAP REQ :" + (wanted.empty() ? std::string("sasl") : wanted));
        }
      } else if (sub == "ACK") {
        std::string acked = message.params.empty() ? std::string() : message.params.back();
        {
          std::lock_guard<std::mutex> lock(mLock);
          for (std::size_t from = 0; from < acked.size();) {
            const std::size_t space = acked.find(' ', from);
            mCaps.insert(acked.substr(from, space == std::string::npos ? std::string::npos : space - from));
            from = space == std::string::npos ? acked.size() : space + 1;
          }
        }
        (void)SendLine("AUTHENTICATE PLAIN");
      } else if (sub == "NAK") {
        Fail("FAF's chat refused its capabilities");
        mSocket.Close();
      }
    } else if (command == "AUTHENTICATE" && param(0) == "+") {
      std::string user;
      std::string token;
      {
        std::lock_guard<std::mutex> lock(mLock);
        user = mWantedNick;
        token = mToken;
      }
      // authzid \0 authcid \0 password, as FAF's clients send it.
      (void)SendLine(
        "AUTHENTICATE " + Base64(user + std::string(1, '\0') + user + std::string(1, '\0') + "token:" + token)
      );
    } else if (command == "903") { // SASL done
      std::string nick;
      {
        std::lock_guard<std::mutex> lock(mLock);
        mToken.clear();
        nick = mNick;
      }
      (void)SendLine("CAP END");
      (void)SendLine("NICK " + nick);
      (void)SendLine("USER " + nick + " 0 * :" + nick);
    } else if (command == "904" || command == "905" || command == "906") {
      Fail("FAF's chat refused the sign-in" + (param(1).empty() ? std::string() : ": " + param(1)));
      mSocket.Close();
    } else if (command == "433") { // nick in use
      std::string nick;
      {
        std::lock_guard<std::mutex> lock(mLock);
        mNick += "_";
        nick = mNick;
      }
      (void)SendLine("NICK " + nick);
    } else if (command == "001") {
      {
        std::lock_guard<std::mutex> lock(mLock);
        if (!param(0).empty()) {
          mNick = param(0);
        }
      }
      Log("signed in as " + Nick());
      mState = State::Joined;
      for (const std::string& channel : mSettings.channels) {
        (void)Join(channel);
      }
    } else if (command == "JOIN") {
      const std::string channel = param(0);
      const bool self = message.nick == Nick();
      {
        std::lock_guard<std::mutex> lock(mLock);
        Channel& kept = mChannels[Lower(channel)];
        kept.users.insert(message.nick);
        if (self && !kept.joined) {
          kept.joined = true;
          if (std::find(mOrder.begin(), mOrder.end(), channel) == mOrder.end()) {
            mOrder.push_back(channel);
          }
        }
      }
      if (self) {
        bool history = false;
        {
          std::lock_guard<std::mutex> lock(mLock);
          history = mCaps.contains("draft/chathistory");
        }
        if (history) {
          (void)SendLine("CHATHISTORY LATEST " + channel + " * " + std::to_string(mSettings.historyLines));
        }
      } else if (!message.tags.contains("batch")) {
        Add(
          channel,
          {message.nick,
           "joined",
           message.tags.contains("time") ? message.tags.at("time") : "",
           false,
           false,
           true,
           false}
        );
      }
    } else if (command == "PART" || command == "QUIT") {
      std::lock_guard<std::mutex> lock(mLock);
      for (auto& [name, kept] : mChannels) {
        if (command == "QUIT" || Lower(param(0)) == name) {
          kept.users.erase(message.nick);
          for (const char* prefix : {"@", "+", "%", "~", "&"}) {
            kept.users.erase(prefix + message.nick);
          }
          if (message.nick == mNick && command == "PART") {
            kept.joined = false;
          }
        }
      }
    } else if (command == "353") { // names: <me> <=|*|@> <channel> :<nicks>
      const std::string channel = message.params.size() >= 3 ? message.params[message.params.size() - 2] : "";
      const std::string nicks = message.params.empty() ? std::string() : message.params.back();
      std::lock_guard<std::mutex> lock(mLock);
      Channel& kept = mChannels[Lower(channel)];
      for (std::size_t from = 0; from < nicks.size();) {
        const std::size_t space = nicks.find(' ', from);
        const std::string nick = nicks.substr(from, space == std::string::npos ? std::string::npos : space - from);
        if (!nick.empty()) {
          kept.users.insert(nick);
        }
        from = space == std::string::npos ? nicks.size() : space + 1;
      }
    } else if (command == "332") { // topic: <me> <channel> :<topic>
      std::lock_guard<std::mutex> lock(mLock);
      mChannels[Lower(param(1))].topic = message.params.empty() ? std::string() : message.params.back();
    } else if (command == "PRIVMSG" || command == "NOTICE") {
      const std::string target = param(0);
      if (target.empty()) {
        return;
      }
      // A private message: a conversation named after the other player (the services' notices stay out).
      const bool isPrivate = target[0] != '#' && target[0] != '&';
      if (isPrivate && (command == "NOTICE" || message.nick.empty() || message.nick.find('.') != std::string::npos)) {
        return;
      }
      const std::string conversation = isPrivate ? (message.nick == Nick() ? target : message.nick) : target;
      if (isPrivate) {
        std::lock_guard<std::mutex> lock(mLock);
        OpenConversation(conversation);
      }
      std::string text = message.params.size() >= 2 ? message.params.back() : std::string();
      bool action = false;
      if (
        text.rfind(
          "\x01"
          "ACTION ",
          0
        ) == 0
      ) {
        action = true;
        text = text.substr(8);
        if (!text.empty() && text.back() == '\x01') {
          text.pop_back();
        }
      }
      FafChatLine line;
      line.from = message.nick;
      line.text = text;
      line.time = message.tags.contains("time") ? message.tags.at("time") : "";
      line.self = message.nick == Nick();
      line.action = action;
      line.event = command == "NOTICE";
      line.history = message.tags.contains("batch");
      Add(conversation, std::move(line));
    } else if (command == "ERROR") {
      Fail("FAF's chat: " + (message.params.empty() ? std::string("error") : message.params.back()));
    }
  }

  std::expected<void, std::string> FafChat::Say(
    const std::string& channel,
    const std::string& text
  )
  {
    if (mState.load() != State::Joined) {
      return std::unexpected(std::string("not in FAF's chat"));
    }
    std::string clean;
    for (const char c : text) {
      if (c != '\r' && c != '\n') {
        clean += c;
      }
    }
    if (clean.find_first_not_of(' ') == std::string::npos) {
      return std::unexpected(std::string("nothing to say"));
    }
    const bool action = clean.rfind("/me ", 0) == 0;
    const std::string body = action ? ("\x01"
                                       "ACTION " +
                                       clean.substr(4) + "\x01")
                                    : clean;
    if (const auto sent = SendLine("PRIVMSG " + channel + " :" + body); !sent) {
      return sent;
    }
    if (!channel.empty() && channel[0] != '#' && channel[0] != '&') {
      std::lock_guard<std::mutex> lock(mLock);
      OpenConversation(channel);
    }
    // The server doesn't send one's own lines back (no echo-message): kept here as they were sent.
    FafChatLine line;
    line.from = Nick();
    line.text = action ? clean.substr(4) : clean;
    line.self = true;
    line.action = action;
    Add(channel, std::move(line));
    return {};
  }

  std::expected<void, std::string> FafChat::Join(
    const std::string& channel
  )
  {
    const std::string name = ChannelName(channel);
    if (name.empty()) {
      return std::unexpected(std::string("not a channel's name"));
    }
    return SendLine("JOIN " + name);
  }

  std::expected<void, std::string> FafChat::Part(
    const std::string& channel
  )
  {
    // A private conversation closes here: there is nothing to leave on the server.
    if (!channel.empty() && channel[0] != '#' && channel[0] != '&') {
      std::lock_guard<std::mutex> lock(mLock);
      if (const auto found = mChannels.find(Lower(channel)); found != mChannels.end()) {
        found->second.joined = false;
      }
      std::erase(mOrder, channel);
      return {};
    }
    const std::string name = ChannelName(channel);
    if (name.empty()) {
      return std::unexpected(std::string("not a channel's name"));
    }
    return SendLine("PART " + name);
  }

  void FafChat::OpenPrivate(
    const std::string& nick
  )
  {
    if (nick.empty() || nick[0] == '#' || nick[0] == '&' || nick.find_first_of(" ,\a\r\n") != std::string::npos) {
      return;
    }
    std::lock_guard<std::mutex> lock(mLock);
    OpenConversation(nick);
  }

  void FafChat::OpenConversation(
    const std::string& nick
  )
  {
    Channel& kept = mChannels[Lower(nick)];
    if (!kept.joined) {
      kept.joined = true;
      kept.users.insert(nick);
    }
    if (std::find(mOrder.begin(), mOrder.end(), nick) == mOrder.end()) {
      mOrder.push_back(nick);
    }
  }
} // namespace faf::online
