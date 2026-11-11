#include "editor/doc/EdFafApi.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iterator>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <dpapi.h>
#include <shellapi.h>

#include "editor/doc/EdHttp.h"
#include <cstdarg>
#include <cstdio>

namespace faf::editor
{
  namespace
  {
    void (*gFafLog)(const char*) = nullptr;

    /** A line to the editor's log, when it set one (SetFafLog). */
    void FafLog(const char* const format, ...)
    {
      if (gFafLog == nullptr) {
        return;
      }
      char line[1024];
      va_list args;
      va_start(args, format);
      (void)std::vsnprintf(line, sizeof(line), format, args);
      va_end(args);
      gFafLog(line);
    }

    struct JsonReader
    {
      const std::string& text;
      std::size_t at = 0;
      std::string error;

      void Space()
      {
        while (at < text.size() && (text[at] == ' ' || text[at] == '\t' || text[at] == '\r' || text[at] == '\n')) {
          ++at;
        }
      }

      static void PutUtf8(std::string& out, std::uint32_t code)
      {
        if (code < 0x80u) {
          out += static_cast<char>(code);
        } else if (code < 0x800u) {
          out += static_cast<char>(0xC0u | (code >> 6));
          out += static_cast<char>(0x80u | (code & 0x3Fu));
        } else if (code < 0x10000u) {
          out += static_cast<char>(0xE0u | (code >> 12));
          out += static_cast<char>(0x80u | ((code >> 6) & 0x3Fu));
          out += static_cast<char>(0x80u | (code & 0x3Fu));
        } else {
          out += static_cast<char>(0xF0u | (code >> 18));
          out += static_cast<char>(0x80u | ((code >> 12) & 0x3Fu));
          out += static_cast<char>(0x80u | ((code >> 6) & 0x3Fu));
          out += static_cast<char>(0x80u | (code & 0x3Fu));
        }
      }

      bool Hex4(std::uint32_t& code)
      {
        if (at + 4 > text.size()) {
          return false;
        }
        code = static_cast<std::uint32_t>(std::strtoul(text.substr(at, 4).c_str(), nullptr, 16));
        at += 4;
        return true;
      }

      bool String(std::string& out)
      {
        ++at; // the opening quote
        while (at < text.size()) {
          const char c = text[at++];
          if (c == '"') {
            return true;
          }
          if (c != '\\') {
            out += c;
            continue;
          }
          if (at >= text.size()) {
            break;
          }
          const char e = text[at++];
          switch (e) {
          case 'n': out += '\n'; break;
          case 't': out += '\t'; break;
          case 'r': out += '\r'; break;
          case 'b': out += '\b'; break;
          case 'f': out += '\f'; break;
          case 'u': {
            std::uint32_t code = 0;
            if (!Hex4(code)) {
              error = "a broken \\u escape";
              return false;
            }
            // A surrogate pair.
            if (code >= 0xD800u && code < 0xDC00u && at + 6 <= text.size() && text[at] == '\\' && text[at + 1] == 'u') {
              at += 2;
              std::uint32_t low = 0;
              if (Hex4(low) && low >= 0xDC00u && low < 0xE000u) {
                code = 0x10000u + ((code - 0xD800u) << 10) + (low - 0xDC00u);
              }
            }
            PutUtf8(out, code);
            break;
          }
          default: out += e; break;
          }
        }
        error = "a string doesn't end";
        return false;
      }

      bool Value(JsonNode& node, const int depth)
      {
        if (depth > 128) {
          error = "nested too deep";
          return false;
        }
        Space();
        if (at >= text.size()) {
          error = "the text ends inside a value";
          return false;
        }
        const char c = text[at];
        if (c == '{') {
          node.kind = JsonNode::Kind::Object;
          ++at;
          Space();
          if (at < text.size() && text[at] == '}') {
            ++at;
            return true;
          }
          for (;;) {
            Space();
            if (at >= text.size() || text[at] != '"') {
              error = "an object's key isn't a string";
              return false;
            }
            std::string key;
            if (!String(key)) {
              return false;
            }
            Space();
            if (at >= text.size() || text[at] != ':') {
              error = "no ':' after a key";
              return false;
            }
            ++at;
            JsonNode child;
            if (!Value(child, depth + 1)) {
              return false;
            }
            node.members.emplace_back(std::move(key), std::move(child));
            Space();
            if (at < text.size() && text[at] == ',') {
              ++at;
              continue;
            }
            if (at < text.size() && text[at] == '}') {
              ++at;
              return true;
            }
            error = "an object doesn't end";
            return false;
          }
        }
        if (c == '[') {
          node.kind = JsonNode::Kind::Array;
          ++at;
          Space();
          if (at < text.size() && text[at] == ']') {
            ++at;
            return true;
          }
          for (;;) {
            JsonNode child;
            if (!Value(child, depth + 1)) {
              return false;
            }
            node.items.push_back(std::move(child));
            Space();
            if (at < text.size() && text[at] == ',') {
              ++at;
              continue;
            }
            if (at < text.size() && text[at] == ']') {
              ++at;
              return true;
            }
            error = "an array doesn't end";
            return false;
          }
        }
        if (c == '"') {
          node.kind = JsonNode::Kind::String;
          return String(node.text);
        }
        if (text.compare(at, 4, "true") == 0 || text.compare(at, 5, "false") == 0) {
          node.kind = JsonNode::Kind::Bool;
          node.boolean = text[at] == 't';
          at += node.boolean ? 4 : 5;
          return true;
        }
        if (text.compare(at, 4, "null") == 0) {
          at += 4;
          return true;
        }
        char* end = nullptr;
        node.number = std::strtod(text.c_str() + at, &end);
        if (end == text.c_str() + at) {
          error = std::string("unexpected '") + c + "'";
          return false;
        }
        node.kind = JsonNode::Kind::Number;
        at = static_cast<std::size_t>(end - text.c_str());
        return true;
      }
    };

    /** `included`'s resource of this type and id, or null. */
    const JsonNode* Included(const JsonNode& root, const JsonNode* const reference)
    {
      const JsonNode* const included = root.Get("included");
      const JsonNode* const data = reference != nullptr ? reference->Get("data") : nullptr;
      if (included == nullptr || data == nullptr || data->kind != JsonNode::Kind::Object) {
        return nullptr;
      }
      const std::string type = data->String("type");
      const std::string id = data->String("id");
      for (const JsonNode& item : included->items) {
        if (item.String("type") == type && item.String("id") == id) {
          return &item;
        }
      }
      return nullptr;
    }

    std::string Form(const std::vector<std::pair<std::string, std::string>>& fields)
    {
      std::string out;
      for (const auto& [key, value] : fields) {
        out += (out.empty() ? "" : "&") + UrlEncode(key) + "=" + UrlEncode(value);
      }
      return out;
    }

    /** A POST to Hydra's token or device endpoint. */
    bool PostForm(const std::string& path, const std::vector<std::pair<std::string, std::string>>& fields, long& status, JsonNode& answer,
                  std::string& error)
    {
      HttpCall call;
      call.method = "POST";
      call.url = std::string(kFafOAuthUrl) + path;
      call.headers = "Content-Type: application/x-www-form-urlencoded\r\nAccept: application/json\r\n";
      call.body = Form(fields);
      std::string body;
      if (!HttpRequest(call, status, body, error)) {
        return false;
      }
      if (!ParseJson(body, answer, error)) {
        error = "FAF's login answered " + std::to_string(status) + " with text that isn't JSON";
        return false;
      }
      return true;
    }
  } // namespace

  void SetFafLog(void (*log)(const char*)) noexcept
  {
    gFafLog = log;
  }

  const JsonNode* JsonNode::Get(const std::string& key) const
  {
    for (const auto& [name, value] : members) {
      if (name == key) {
        return &value;
      }
    }
    return nullptr;
  }

  std::string JsonNode::String(const std::string& key) const
  {
    const JsonNode* const value = Get(key);
    if (value == nullptr) {
      return {};
    }
    if (value->kind == Kind::Number) {
      const double n = value->number;
      return std::floor(n) == n ? std::to_string(static_cast<long long>(n)) : std::to_string(n);
    }
    return value->kind == Kind::String ? value->text : std::string();
  }

  double JsonNode::Number(const std::string& key, const double fallback) const
  {
    const JsonNode* const value = Get(key);
    return value != nullptr && value->kind == Kind::Number ? value->number : fallback;
  }

  bool JsonNode::Bool(const std::string& key) const
  {
    const JsonNode* const value = Get(key);
    return value != nullptr && value->kind == Kind::Bool && value->boolean;
  }

  bool ParseJson(const std::string& text, JsonNode& out, std::string& error)
  {
    JsonReader reader{text, 0, {}};
    out = JsonNode{};
    if (!reader.Value(out, 0)) {
      error = reader.error;
      return false;
    }
    reader.Space();
    if (reader.at != text.size()) {
      error = "text after the value";
      return false;
    }
    return true;
  }

  namespace
  {
    /** Text for a quoted RSQL value: quotes and backslashes left out. */
    std::string Unquoted(const std::string& text)
    {
      std::string out;
      for (const char c : text) {
        if (c != '"' && c != '\\') {
          out += c;
        }
      }
      return out;
    }

    /** "YYYY-MM-DD", checked. */
    bool IsDate(const std::string& text)
    {
      if (text.size() != 10 || text[4] != '-' || text[7] != '-') {
        return false;
      }
      for (const std::size_t i : {0U, 1U, 2U, 3U, 5U, 6U, 8U, 9U}) {
        if (text[i] < '0' || text[i] > '9') {
          return false;
        }
      }
      return true;
    }

    std::string Sizes(const unsigned bits)
    {
      std::string out;
      for (int k = 0; k < 7; ++k) {
        if ((bits & (1U << k)) != 0) {
          out += (out.empty() ? "\"" : ",\"") + std::to_string(kVaultSizes[k]) + "\"";
        }
      }
      return out;
    }

    std::string Number(const float value)
    {
      char text[32];
      (void)std::snprintf(text, sizeof(text), "%g", static_cast<double>(value));
      return text;
    }
  } // namespace

  std::string VaultQueryFilter(const VaultQuery& query)
  {
    // The FAF client's filters in its order, each condition as its QBuilder writes it, then the hidden versions left out.
    std::vector<std::string> conditions;
    if (const std::string name = Unquoted(query.text); !name.empty()) {
      conditions.push_back("displayName==\"*" + name + "*\"");
    }
    if (const std::string author = Unquoted(query.author); !author.empty()) {
      conditions.push_back("author.login==\"*" + author + "*\"");
    }
    if (IsDate(query.uploadedFrom)) {
      conditions.push_back("latestVersion.updateTime=gt=\"" + query.uploadedFrom + "T00:00:00Z\"");
    }
    if (IsDate(query.uploadedTo)) {
      conditions.push_back("latestVersion.updateTime=lt=\"" + query.uploadedTo + "T00:00:00Z\"");
    }
    if (query.widths != 0) {
      conditions.push_back("latestVersion.width=in=(" + Sizes(query.widths) + ")");
    }
    if (query.heights != 0) {
      conditions.push_back("latestVersion.height=in=(" + Sizes(query.heights) + ")");
    }
    if (query.minPlayers > 0) {
      conditions.push_back("latestVersion.maxPlayers=ge=" + std::to_string(query.minPlayers));
    }
    if (query.maxPlayers > 0 && query.maxPlayers < 16) {
      conditions.push_back("latestVersion.maxPlayers=le=" + std::to_string(query.maxPlayers));
    }
    if (query.minScore > 0.0f) {
      conditions.push_back("reviewsSummary.averageScore=ge=" + Number(query.minScore));
    }
    if (query.maxScore < 5.0f) {
      conditions.push_back("reviewsSummary.averageScore=le=" + Number(query.maxScore));
    }
    if (query.rankedOnly) {
      conditions.push_back("latestVersion.ranked==\"true\"");
    }
    conditions.push_back("latestVersion.hidden==false");
    std::string filter;
    for (const std::string& condition : conditions) {
      filter += (filter.empty() ? "" : ";") + condition;
    }
    return filter;
  }

  std::string VaultSearchUrl(const VaultQuery& query, const int page)
  {
    const std::string sort = (query.descending ? "-" : "") + (query.sortProperty.empty() ? std::string("gamesPlayed") : query.sortProperty);
    return std::string(kFafApiUrl) + "/data/map?filter=" + UrlEncode(VaultQueryFilter(query)) + "&include=latestVersion,author&sort=" + sort +
           "&page%5Bsize%5D=30&page%5Bnumber%5D=" + std::to_string(std::max(page, 1)) + "&page%5Btotals%5D";
  }

  std::string VaultQueryText(const VaultQuery& q)
  {
    // key=value separated by tabs (no field holds a tab: the panel's fields are single lines).
    const auto clean = [](std::string text) {
      for (char& c : text) {
        c = (c == '\t' || c == '\n' || c == '\r') ? ' ' : c;
      }
      return text;
    };
    return "name=" + clean(q.text) + "\tauthor=" + clean(q.author) + "\tfrom=" + clean(q.uploadedFrom) + "\tto=" + clean(q.uploadedTo) +
           "\twidths=" + std::to_string(q.widths) + "\theights=" + std::to_string(q.heights) + "\tplayersFrom=" + std::to_string(q.minPlayers) +
           "\tplayersTo=" + std::to_string(q.maxPlayers) + "\tscoreFrom=" + Number(q.minScore) + "\tscoreTo=" + Number(q.maxScore) +
           "\tranked=" + (q.rankedOnly ? "1" : "0") + "\tsort=" + clean(q.sortProperty) + "\tdescending=" + (q.descending ? "1" : "0");
  }

  bool VaultQueryFromText(const std::string& text, VaultQuery& out)
  {
    VaultQuery q;
    bool any = false;
    std::size_t at = 0;
    while (at <= text.size()) {
      const std::size_t tab = text.find('\t', at);
      const std::string field = text.substr(at, tab == std::string::npos ? std::string::npos : tab - at);
      at = tab == std::string::npos ? text.size() + 1 : tab + 1;
      const std::size_t eq = field.find('=');
      if (eq == std::string::npos) {
        continue;
      }
      const std::string key = field.substr(0, eq);
      const std::string value = field.substr(eq + 1);
      any = true;
      if (key == "name") {
        q.text = value;
      } else if (key == "author") {
        q.author = value;
      } else if (key == "from") {
        q.uploadedFrom = value;
      } else if (key == "to") {
        q.uploadedTo = value;
      } else if (key == "widths") {
        q.widths = static_cast<unsigned>(std::strtoul(value.c_str(), nullptr, 10)) & 0x7FU;
      } else if (key == "heights") {
        q.heights = static_cast<unsigned>(std::strtoul(value.c_str(), nullptr, 10)) & 0x7FU;
      } else if (key == "playersFrom") {
        q.minPlayers = std::clamp(std::atoi(value.c_str()), 0, 16);
      } else if (key == "playersTo") {
        q.maxPlayers = std::clamp(std::atoi(value.c_str()), 0, 16);
      } else if (key == "scoreFrom") {
        q.minScore = std::clamp(static_cast<float>(std::atof(value.c_str())), 0.0f, 5.0f);
      } else if (key == "scoreTo") {
        q.maxScore = std::clamp(static_cast<float>(std::atof(value.c_str())), 0.0f, 5.0f);
      } else if (key == "ranked") {
        q.rankedOnly = value == "1";
      } else if (key == "sort") {
        q.sortProperty = value;
      } else if (key == "descending") {
        q.descending = value == "1";
      }
    }
    if (any) {
      out = q;
    }
    return any;
  }

  bool ParseVaultSearch(const std::string& json, std::vector<VaultMap>& maps, int& pages, std::string& error)
  {
    JsonNode root;
    if (!ParseJson(json, root, error)) {
      return false;
    }
    if (const JsonNode* const errors = root.Get("errors"); errors != nullptr && !errors->items.empty()) {
      error = errors->items.front().String("detail");
      if (error.empty()) {
        error = errors->items.front().String("title");
      }
      return false;
    }
    const JsonNode* const data = root.Get("data");
    if (data == nullptr || data->kind != JsonNode::Kind::Array) {
      error = "the answer has no maps";
      return false;
    }
    for (const JsonNode& item : data->items) {
      const JsonNode* const attributes = item.Get("attributes");
      const JsonNode* const relationships = item.Get("relationships");
      if (attributes == nullptr) {
        continue;
      }
      VaultMap map;
      map.name = attributes->String("displayName");
      map.gamesPlayed = static_cast<int>(attributes->Number("gamesPlayed"));
      const JsonNode* const version = relationships != nullptr ? Included(root, relationships->Get("latestVersion")) : nullptr;
      if (version == nullptr || version->Get("attributes") == nullptr) {
        continue; // no version to download
      }
      const JsonNode& v = *version->Get("attributes");
      map.folder = v.String("folderName");
      map.version = v.String("version");
      map.description = v.String("description");
      map.thumbnail = v.String("thumbnailUrlLarge");
      if (map.thumbnail.empty()) {
        map.thumbnail = v.String("thumbnailUrlSmall");
      }
      map.players = static_cast<int>(v.Number("maxPlayers"));
      map.width = static_cast<int>(v.Number("width"));
      map.height = static_cast<int>(v.Number("height"));
      map.ranked = v.Bool("ranked");
      if (const JsonNode* const author = relationships != nullptr ? Included(root, relationships->Get("author")) : nullptr) {
        if (const JsonNode* const a = author->Get("attributes")) {
          map.author = a->String("login");
        }
      }
      if (!map.folder.empty()) {
        maps.push_back(std::move(map));
      }
    }
    pages = 1;
    if (const JsonNode* const meta = root.Get("meta")) {
      if (const JsonNode* const page = meta->Get("page")) {
        pages = std::max(1, static_cast<int>(page->Number("totalPages", 1.0)));
      }
    }
    return true;
  }

  EdFafSession::~EdFafSession()
  {
    mStop = true;
    for (std::thread& thread : mThreads) {
      if (thread.joinable()) {
        thread.join();
      }
    }
  }

  void EdFafSession::Run(std::function<void()> job)
  {
    mThreads.emplace_back(std::move(job));
  }

  void EdFafSession::SetMessage(std::string text)
  {
    if (!text.empty()) {
      FafLog("editor: FAF: %s", text.c_str());
    }
    std::lock_guard<std::mutex> lock(mLock);
    mMessage = std::move(text);
  }

  std::string EdFafSession::UserName() const
  {
    std::lock_guard<std::mutex> lock(mLock);
    return mUserName;
  }

  int EdFafSession::SecondsLeft() const
  {
    const long long now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
    return static_cast<int>(std::max<long long>(0, mCodeExpires.load() - now));
  }

  void EdFafSession::CancelLogin()
  {
    mCancel = true;
  }

  void EdFafSession::FetchUserName()
  {
    // The API's own record of who is logged in (the FAF client's /me).
    HttpCall call;
    call.url = std::string(kFafApiUrl) + "/me";
    {
      std::lock_guard<std::mutex> lock(mLock);
      call.headers = "Accept: application/json\r\nAuthorization: Bearer " + mAccessToken + "\r\n";
    }
    long status = 0;
    std::string body;
    std::string error;
    JsonNode me;
    if (!HttpRequest(call, status, body, error) || status != 200 || !ParseJson(body, me, error)) {
      FafLog("editor: FAF: /me answered %ld%s%s", status, error.empty() ? "" : ": ", error.c_str());
      return;
    }
    std::string name;
    if (const JsonNode* const data = me.Get("data")) {
      if (const JsonNode* const attributes = data->Get("attributes")) {
        name = attributes->String("userName");
        if (name.empty()) {
          name = attributes->String("login");
        }
      }
    }
    FafLog("editor: FAF: logged in as %s", name.empty() ? "(no name in /me)" : name.c_str());
    std::lock_guard<std::mutex> lock(mLock);
    mUserName = name;
  }

  std::string EdFafSession::Message() const
  {
    std::lock_guard<std::mutex> lock(mLock);
    return mMessage;
  }

  std::string EdFafSession::UserCode() const
  {
    std::lock_guard<std::mutex> lock(mLock);
    return mUserCode;
  }

  std::string EdFafSession::VerifyUrl() const
  {
    std::lock_guard<std::mutex> lock(mLock);
    return mVerifyUrl;
  }

  void EdFafSession::SetTokenFile(std::filesystem::path file)
  {
    mTokenFile = std::move(file);
    std::ifstream in(mTokenFile, std::ios::binary);
    const std::string sealed((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (sealed.empty()) {
      return;
    }
    DATA_BLOB input{static_cast<DWORD>(sealed.size()), reinterpret_cast<BYTE*>(const_cast<char*>(sealed.data()))};
    DATA_BLOB output{};
    if (::CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, 0, &output)) {
      std::lock_guard<std::mutex> lock(mLock);
      mRefreshToken.assign(reinterpret_cast<const char*>(output.pbData), output.cbData);
      ::LocalFree(output.pbData);
    }
  }

  void EdFafSession::SaveRefreshToken() const
  {
    if (mTokenFile.empty()) {
      return;
    }
    std::string token;
    {
      std::lock_guard<std::mutex> lock(mLock);
      token = mRefreshToken;
    }
    std::ofstream out(mTokenFile, std::ios::binary | std::ios::trunc);
    if (token.empty()) {
      return;
    }
    DATA_BLOB input{static_cast<DWORD>(token.size()), reinterpret_cast<BYTE*>(token.data())};
    DATA_BLOB output{};
    if (::CryptProtectData(&input, L"FAF map editor login", nullptr, nullptr, nullptr, 0, &output)) {
      out.write(reinterpret_cast<const char*>(output.pbData), output.cbData);
      ::LocalFree(output.pbData);
    }
  }

  bool EdFafSession::RefreshAccess(std::string& error)
  {
    std::string refresh;
    {
      std::lock_guard<std::mutex> lock(mLock);
      refresh = mRefreshToken;
    }
    if (refresh.empty()) {
      error = "not logged in";
      return false;
    }
    long status = 0;
    JsonNode answer;
    if (!PostForm("/oauth2/token", {{"grant_type", "refresh_token"}, {"refresh_token", refresh}, {"client_id", kFafClientId}}, status, answer,
                  error)) {
      return false;
    }
    if (status != 200 || answer.String("access_token").empty()) {
      error = "FAF's login refused the kept login (" + answer.String("error") + "); log in again";
      std::lock_guard<std::mutex> lock(mLock);
      mRefreshToken.clear();
      return false;
    }
    {
      std::lock_guard<std::mutex> lock(mLock);
      mAccessToken = answer.String("access_token");
      if (!answer.String("refresh_token").empty()) {
        mRefreshToken = answer.String("refresh_token"); // Hydra hands out a new one each time
      }
    }
    SaveRefreshToken();
    return true;
  }

  void EdFafSession::Resume()
  {
    {
      std::lock_guard<std::mutex> lock(mLock);
      if (mRefreshToken.empty() || mState.load() != State::LoggedOut) {
        return;
      }
    }
    mState = State::Working;
    SetMessage("Logging in to FAF...");
    Run([this] {
      std::string error;
      if (RefreshAccess(error)) {
        FetchUserName();
        mState = State::LoggedIn;
        SetMessage("Logged in to FAF");
      } else {
        mState = State::LoggedOut;
        SetMessage(error);
        SaveRefreshToken();
      }
    });
  }

  void EdFafSession::StartLogin()
  {
    if (mState.load() == State::Working || mState.load() == State::WaitingForApproval) {
      return;
    }
    mState = State::Working;
    mCancel = false;
    SetMessage("Asking FAF for a login code...");
    Run([this] {
      long status = 0;
      JsonNode device;
      std::string error;
      if (!PostForm("/oauth2/device/auth", {{"client_id", kFafClientId}, {"scope", kFafScopes}}, status, device, error) || status != 200) {
        mState = State::LoggedOut;
        SetMessage(error.empty() ? "FAF's login answered " + std::to_string(status) : error);
        return;
      }
      const std::string deviceCode = device.String("device_code");
      {
        std::lock_guard<std::mutex> lock(mLock);
        mUserCode = device.String("user_code");
        mVerifyUrl = device.String("verification_uri_complete");
        if (mVerifyUrl.empty()) {
          mVerifyUrl = device.String("verification_uri");
        }
      }
      // FAF's page in the browser, the code already in it (as the FAF client opens it): the panel opens it on the
      // UI thread, as ShellExecute needs COM set up where it runs.
      mOpenPage = true;
      mState = State::WaitingForApproval;
      SetMessage("Approve the editor on FAF's page in your browser (code " + UserCode() + ")");
      int interval = std::max(1, static_cast<int>(device.Number("interval", 5.0)));
      const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(static_cast<int>(device.Number("expires_in", 600.0)));
      mCodeExpires = std::chrono::duration_cast<std::chrono::seconds>(until.time_since_epoch()).count();
      std::string lastPoll;
      while (!mStop.load() && !mCancel.load() && std::chrono::steady_clock::now() < until) {
        for (int i = 0; i < interval * 10 && !mStop.load() && !mCancel.load(); ++i) {
          std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (mStop.load() || mCancel.load()) {
          break;
        }
        JsonNode token;
        const bool answered = PostForm(
          "/oauth2/token", {{"grant_type", "urn:ietf:params:oauth:grant-type:device_code"}, {"device_code", deviceCode}, {"client_id", kFafClientId}},
          status, token, error);
        // Each new kind of answer once in the log, so a login that never ends says why.
        const std::string poll = std::to_string(status) + " " + (answered ? token.String("error") : error);
        if (poll != lastPoll) {
          FafLog("editor: FAF: waiting for approval, the token endpoint answers %s", poll.c_str());
          lastPoll = poll;
        }
        if (!answered) {
          continue; // a dropped answer: ask again
        }
        if (status == 200 && !token.String("access_token").empty()) {
          {
            std::lock_guard<std::mutex> lock(mLock);
            mAccessToken = token.String("access_token");
            mRefreshToken = token.String("refresh_token");
          }
          SaveRefreshToken();
          FetchUserName();
          mState = State::LoggedIn;
          SetMessage("Logged in to FAF");
          return;
        }
        const std::string why = token.String("error");
        if (why == "slow_down") {
          interval += 5;
        } else if (why != "authorization_pending") {
          mState = State::LoggedOut;
          SetMessage(why == "access_denied" ? "The login was declined on FAF's page" : "FAF's login stopped: " + why);
          return;
        }
      }
      if (mCancel.load()) {
        mState = State::LoggedOut;
        SetMessage("Sign-in cancelled");
      } else if (!mStop.load()) {
        mState = State::LoggedOut;
        SetMessage("The sign-in code ran out before it was approved; sign in again");
      }
    });
  }

  void EdFafSession::Logout()
  {
    {
      std::lock_guard<std::mutex> lock(mLock);
      mAccessToken.clear();
      mRefreshToken.clear();
      mUserName.clear();
    }
    SaveRefreshToken();
    mState = State::LoggedOut;
    SetMessage("Logged out of FAF");
  }

  void EdFafSession::Search(const VaultQuery& query, const int page)
  {
    if (mState.load() != State::LoggedIn || mSearching.exchange(true)) {
      return;
    }
    Run([this, query, page] {
      std::string error;
      std::vector<VaultMap> maps;
      int pages = 0;
      for (int attempt = 0; attempt < 2; ++attempt) {
        HttpCall call;
        call.url = VaultSearchUrl(query, page);
        {
          std::lock_guard<std::mutex> lock(mLock);
          call.headers = "Accept: application/vnd.api+json\r\nAuthorization: Bearer " + mAccessToken + "\r\n";
        }
        long status = 0;
        std::string body;
        if (!HttpRequest(call, status, body, error)) {
          break;
        }
        if (status == 401 && attempt == 0) {
          // The access token lasts an hour: a new one from the refresh token, then the search again.
          if (!RefreshAccess(error)) {
            mState = State::LoggedOut;
            break;
          }
          continue;
        }
        if (status != 200) {
          // The API says what it didn't take (a filter or an order it doesn't know).
          JsonNode answer;
          std::string detail;
          if (ParseJson(body, answer, detail)) {
            if (const JsonNode* const errors = answer.Get("errors"); errors != nullptr && !errors->items.empty()) {
              detail = errors->items.front().String("detail");
            }
          }
          error = "FAF's map API answered " + std::to_string(status) + (detail.empty() ? "" : ": " + detail);
          break;
        }
        if (!ParseVaultSearch(body, maps, pages, error)) {
          break;
        }
        error.clear();
        break;
      }
      {
        std::lock_guard<std::mutex> lock(mLock);
        mResults = std::move(maps);
        mPages = pages;
        mHaveResults = true;
      }
      SetMessage(error.empty() ? std::string() : error);
      mSearching = false;
    });
  }

  bool EdFafSession::TakeResults(std::vector<VaultMap>& maps, int& pages)
  {
    std::lock_guard<std::mutex> lock(mLock);
    if (!mHaveResults) {
      return false;
    }
    mHaveResults = false;
    maps = std::move(mResults);
    pages = mPages;
    return true;
  }

  std::string EdFafSession::Picture(const std::string& url)
  {
    if (url.empty()) {
      return {};
    }
    std::lock_guard<std::mutex> lock(mLock);
    if (const auto found = mPictures.find(url); found != mPictures.end()) {
      return found->second;
    }
    if (std::find(mPictureQueue.begin(), mPictureQueue.end(), url) == mPictureQueue.end()) {
      mPictureQueue.push_back(url);
    }
    if (!mPictureWorker) {
      mPictureWorker = true;
      mThreads.emplace_back([this] {
        for (;;) {
          std::string next;
          {
            std::lock_guard<std::mutex> guard(mLock);
            if (mPictureQueue.empty() || mStop.load()) {
              mPictureWorker = false;
              return;
            }
            next = mPictureQueue.front();
            mPictureQueue.erase(mPictureQueue.begin());
          }
          // The link's last part is the file's name in both caches ("maps/previews/large/x.png" -> "large/x.png").
          const std::string file = next.substr(next.find_last_of('/') + 1);
          const std::string size = next.find("/small/") != std::string::npos ? "small" : "large";
          std::string body;
          const auto readFile = [&](const std::filesystem::path& path) {
            std::ifstream in(path, std::ios::binary);
            body.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
            return !body.empty();
          };
          char programData[MAX_PATH] = "";
          (void)::GetEnvironmentVariableA("ProgramData", programData, MAX_PATH);
          const std::filesystem::path client = std::filesystem::path(programData) / "FAForever" / "cache" / "maps" / size / file;
          const std::filesystem::path own = mPictureCache.empty() ? std::filesystem::path() : mPictureCache / size / file;
          bool ok = (programData[0] != '\0' && readFile(client)) || (!own.empty() && readFile(own));
          if (!ok) {
            HttpCall call;
            call.url = next;
            long status = 0;
            std::string error;
            ok = HttpRequest(call, status, body, error) && status == 200 && !body.empty();
            if (ok && !own.empty()) {
              std::error_code code;
              std::filesystem::create_directories(own.parent_path(), code);
              std::ofstream out(own, std::ios::binary | std::ios::trunc);
              out.write(body.data(), static_cast<std::streamsize>(body.size()));
            }
          }
          std::lock_guard<std::mutex> guard(mLock);
          mPictures[next] = ok ? body : std::string("\0", 1); // one byte: tried and failed
        }
      });
    }
    return {};
  }
} // namespace faf::editor
