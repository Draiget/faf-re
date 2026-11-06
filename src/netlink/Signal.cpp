#include "netlink/Signal.h"

#include <charconv>
#include <sstream>

namespace faf::netlink
{
  const char* CandidateTypeName(const CandidateType type)
  {
    switch (type) {
      case CandidateType::Host: return "HOST_CANDIDATE";
      case CandidateType::ServerReflexive: return "SERVER_REFLEXIVE_CANDIDATE";
      case CandidateType::PeerReflexive: return "PEER_REFLEXIVE_CANDIDATE";
      case CandidateType::Relayed: return "RELAYED_CANDIDATE";
      case CandidateType::Local: return "LOCAL_CANDIDATE";
      case CandidateType::Stun: return "STUN_CANDIDATE";
    }
    return "HOST_CANDIDATE";
  }

  std::optional<CandidateType> ParseCandidateType(const std::string_view name)
  {
    for (const CandidateType t : {CandidateType::Host, CandidateType::ServerReflexive, CandidateType::PeerReflexive,
                                  CandidateType::Relayed, CandidateType::Local, CandidateType::Stun}) {
      if (name == CandidateTypeName(t)) {
        return t;
      }
    }
    return std::nullopt;
  }

  std::string ToJson(const CandidatesMessage& msg)
  {
    JsonValue candidates = JsonValue::Array();
    for (const Candidate& c : msg.candidates) {
      JsonValue o = JsonValue::Object();
      o.Set("foundation", c.foundation);
      o.Set("protocol", c.protocol);
      o.Set("priority", c.priority);
      o.Set("ip", c.ip);
      o.Set("port", c.port);
      o.Set("type", CandidateTypeName(c.type));
      o.Set("generation", c.generation);
      o.Set("id", c.id);
      o.Set("relAddr", c.relAddr ? JsonValue(*c.relAddr) : JsonValue());
      o.Set("relPort", c.relPort);
      candidates.Push(std::move(o));
    }
    JsonValue o = JsonValue::Object();
    o.Set("srcId", msg.srcId);
    o.Set("destId", msg.destId);
    o.Set("password", msg.password);
    o.Set("ufrag", msg.ufrag);
    o.Set("candidates", std::move(candidates));
    if (!msg.fafPath.empty()) {
      o.Set("fafPath", msg.fafPath);
    }
    return WriteJson(o);
  }

  std::optional<CandidatesMessage> CandidatesMessageFromJson(const std::string_view text, std::string* error)
  {
    const std::optional<JsonValue> doc = ParseJson(text, error);
    if (!doc || !doc->IsObject()) {
      if (error != nullptr && doc) {
        *error = "not an object";
      }
      return std::nullopt;
    }
    const JsonValue& list = doc->Get("candidates");
    if (!list.IsArray()) {
      if (error != nullptr) {
        *error = "candidates missing";
      }
      return std::nullopt;
    }
    CandidatesMessage msg;
    msg.srcId = doc->Get("srcId").AsInt();
    msg.destId = doc->Get("destId").AsInt();
    msg.password = doc->Get("password").AsString();
    msg.ufrag = doc->Get("ufrag").AsString();
    if (const JsonValue* path = doc->Find("fafPath"); path != nullptr) {
      msg.fafPath = path->AsString();
    }
    for (const JsonValue& o : list.Items()) {
      Candidate c;
      c.foundation = o.Get("foundation").AsString();
      c.protocol = o.Get("protocol").AsString();
      c.priority = o.Get("priority").AsInt();
      c.ip = o.Get("ip").AsString();
      c.port = static_cast<int>(o.Get("port").AsInt());
      const std::optional<CandidateType> type = ParseCandidateType(o.Get("type").AsString());
      if (!type) {
        if (error != nullptr) {
          *error = "unknown candidate type " + o.Get("type").AsString();
        }
        return std::nullopt;
      }
      c.type = *type;
      c.generation = static_cast<int>(o.Get("generation").AsInt());
      c.id = o.Get("id").AsString();
      if (const JsonValue& rel = o.Get("relAddr"); rel.IsString()) {
        c.relAddr = rel.AsString();
      }
      c.relPort = static_cast<int>(o.Get("relPort").AsInt());
      msg.candidates.push_back(std::move(c));
    }
    return msg;
  }

  namespace
  {
    std::vector<std::string_view> Words(std::string_view s)
    {
      std::vector<std::string_view> out;
      std::size_t i = 0;
      while (i < s.size()) {
        while (i < s.size() && (s[i] == ' ' || s[i] == '\r' || s[i] == '\n')) {
          ++i;
        }
        const std::size_t start = i;
        while (i < s.size() && s[i] != ' ' && s[i] != '\r' && s[i] != '\n') {
          ++i;
        }
        if (i > start) {
          out.push_back(s.substr(start, i - start));
        }
      }
      return out;
    }

    template <typename T>
    bool Number(const std::string_view s, T& out)
    {
      const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), out);
      return ec == std::errc() && p == s.data() + s.size();
    }
  } // namespace

  std::optional<Candidate> CandidateFromSdp(std::string_view line)
  {
    if (line.substr(0, 2) == "a=") {
      line.remove_prefix(2);
    }
    if (line.substr(0, 10) != "candidate:") {
      return std::nullopt;
    }
    line.remove_prefix(10);
    const std::vector<std::string_view> w = Words(line);
    // foundation component transport priority ip port "typ" type ...
    if (w.size() < 8 || w[6] != "typ") {
      return std::nullopt;
    }
    Candidate c;
    c.foundation = std::string(w[0]);
    std::string proto(w[2]);
    for (char& ch : proto) {
      ch = static_cast<char>(ch >= 'A' && ch <= 'Z' ? ch - 'A' + 'a' : ch);
    }
    c.protocol = proto;
    if (!Number(w[3], c.priority) || !Number(w[5], c.port)) {
      return std::nullopt;
    }
    c.ip = std::string(w[4]);
    if (w[7] == "host") {
      c.type = CandidateType::Host;
    } else if (w[7] == "srflx") {
      c.type = CandidateType::ServerReflexive;
    } else if (w[7] == "prflx") {
      c.type = CandidateType::PeerReflexive;
    } else if (w[7] == "relay") {
      c.type = CandidateType::Relayed;
    } else {
      return std::nullopt;
    }
    for (std::size_t i = 8; i + 1 < w.size(); i += 2) {
      if (w[i] == "raddr") {
        c.relAddr = std::string(w[i + 1]);
      } else if (w[i] == "rport") {
        Number(w[i + 1], c.relPort);
      }
    }
    // libjuice writes "raddr 0.0.0.0 rport 0" when it hides the base; ice4j
    // sends null / 0 then.
    if (c.relAddr && (*c.relAddr == "0.0.0.0" || *c.relAddr == "::") && c.relPort == 0) {
      c.relAddr.reset();
    }
    return c;
  }

  std::string CandidateToSdp(const Candidate& c)
  {
    const char* typ = "host";
    switch (c.type) {
      case CandidateType::Host:
      case CandidateType::Local:
        typ = "host";
        break;
      case CandidateType::ServerReflexive:
      case CandidateType::Stun:
        typ = "srflx";
        break;
      case CandidateType::PeerReflexive:
        typ = "prflx";
        break;
      case CandidateType::Relayed:
        typ = "relay";
        break;
    }
    std::ostringstream s;
    s << "a=candidate:" << (c.foundation.empty() ? "1" : c.foundation) << " 1 UDP " << c.priority << ' ' << c.ip
      << ' ' << c.port << " typ " << typ;
    if (c.relAddr && c.relPort > 0) {
      s << " raddr " << *c.relAddr << " rport " << c.relPort;
    }
    return s.str();
  }

  namespace
  {
    void AddUrl(std::vector<IceServer>& out, std::string_view url, const std::string& user, const std::string& cred)
    {
      IceServer s;
      if (url.substr(0, 5) == "stun:") {
        s.kind = IceServer::Kind::Stun;
        url.remove_prefix(5);
      } else if (url.substr(0, 5) == "turn:") {
        s.kind = IceServer::Kind::Turn;
        url.remove_prefix(5);
      } else {
        return; // turns:, stuns: and anything else
      }
      if (url.substr(0, 2) == "//") {
        url.remove_prefix(2);
      }
      std::string_view query;
      if (const std::size_t q = url.find('?'); q != std::string_view::npos) {
        query = url.substr(q + 1);
        url = url.substr(0, q);
      }
      if (query.find("transport=tcp") != std::string_view::npos) {
        return;
      }
      if (!url.empty() && url.front() == '[') { // [v6]:port
        const std::size_t close = url.find(']');
        if (close == std::string_view::npos) {
          return;
        }
        s.host = std::string(url.substr(1, close - 1));
        url.remove_prefix(close + 1);
        if (!url.empty() && url.front() == ':') {
          Number(url.substr(1), s.port);
        }
      } else if (const std::size_t colon = url.rfind(':'); colon != std::string_view::npos) {
        s.host = std::string(url.substr(0, colon));
        Number(url.substr(colon + 1), s.port);
      } else {
        s.host = std::string(url);
      }
      if (s.host.empty()) {
        return;
      }
      s.username = user;
      s.credential = cred;
      out.push_back(std::move(s));
    }
  } // namespace

  std::vector<IceServer> ParseIceServers(const JsonValue& list)
  {
    std::vector<IceServer> out;
    for (const JsonValue& entry : list.Items()) {
      const std::string& user = entry.Get("username").AsString();
      const std::string& cred = entry.Get("credential").AsString();
      if (const JsonValue& urls = entry.Get("urls"); urls.IsArray()) {
        for (const JsonValue& u : urls.Items()) {
          AddUrl(out, u.AsString(), user, cred);
        }
      } else if (urls.IsString()) {
        AddUrl(out, urls.AsString(), user, cred);
      }
      if (const JsonValue& url = entry.Get("url"); url.IsString()) {
        AddUrl(out, url.AsString(), user, cred);
      }
    }
    return out;
  }
} // namespace faf::netlink
