#include "editor/doc/EdFafApi.h"

#include <sstream>

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
#include <shellapi.h>

#include "online/Url.h"
#include "platform/Http.h"
#include <cstdarg>
#include <cstdio>

namespace faf::editor
{
  namespace
  {
    void (*gFafLog)(const char*) = nullptr;

    /** A line to the editor's log, when it set one (SetFafLog). */
    void FafLog(
      const char* const format,
      ...
    )
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

    /** `included`'s resource of this type and id, or null. */
    const JsonNode* Included(
      const JsonNode& root,
      const JsonNode* const reference
    )
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

  } // namespace

  void SetFafLog(
    void (*log)(const char*)
  ) noexcept
  {
    gFafLog = log;
  }

  namespace
  {
    /** Text for a quoted RSQL value: quotes and backslashes left out. */
    std::string Unquoted(
      const std::string& text
    )
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
    bool IsDate(
      const std::string& text
    )
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

    std::string Sizes(
      const unsigned bits
    )
    {
      std::string out;
      for (int k = 0; k < 7; ++k) {
        if ((bits & (1U << k)) != 0) {
          out += (out.empty() ? "\"" : ",\"") + std::to_string(kVaultSizes[k]) + "\"";
        }
      }
      return out;
    }

    std::string Number(
      const float value
    )
    {
      char text[32];
      (void)std::snprintf(text, sizeof(text), "%g", static_cast<double>(value));
      return text;
    }
  } // namespace

  std::string VaultQueryFilter(
    const VaultQuery& query
  )
  {
    // The FAF client's filters in its order, each condition as its QBuilder writes it, then the hidden versions left
    // out.
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

  std::string VaultSearchUrl(
    const VaultQuery& query,
    const int page
  )
  {
    const std::string sort =
      (query.descending ? "-" : "") + (query.sortProperty.empty() ? std::string("gamesPlayed") : query.sortProperty);
    return std::string(kFafApiUrl) + "/data/map?filter=" + online::UrlEncode(VaultQueryFilter(query)) +
      "&include=latestVersion,author&sort=" + sort +
      "&page%5Bsize%5D=30&page%5Bnumber%5D=" + std::to_string(std::max(page, 1)) + "&page%5Btotals%5D";
  }

  std::string VaultQueryText(
    const VaultQuery& q
  )
  {
    // key=value separated by tabs (no field holds a tab: the panel's fields are single lines).
    const auto clean = [](std::string text) {
      for (char& c : text) {
        c = (c == '\t' || c == '\n' || c == '\r') ? ' ' : c;
      }
      return text;
    };
    return "name=" + clean(q.text) + "\tauthor=" + clean(q.author) + "\tfrom=" + clean(q.uploadedFrom) +
      "\tto=" + clean(q.uploadedTo) + "\twidths=" + std::to_string(q.widths) +
      "\theights=" + std::to_string(q.heights) + "\tplayersFrom=" + std::to_string(q.minPlayers) +
      "\tplayersTo=" + std::to_string(q.maxPlayers) + "\tscoreFrom=" + Number(q.minScore) +
      "\tscoreTo=" + Number(q.maxScore) + "\tranked=" + (q.rankedOnly ? "1" : "0") + "\tsort=" + clean(q.sortProperty) +
      "\tdescending=" + (q.descending ? "1" : "0");
  }

  bool VaultQueryFromText(
    const std::string& text,
    VaultQuery& out
  )
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

  std::expected<void, std::string> ParseVaultSearch(
    const std::string& json,
    std::vector<VaultMap>& maps,
    int& pages
  )
  {
    const auto parsed = ParseJson(json);
    if (!parsed) {
      return std::unexpected(parsed.error());
    }
    const JsonNode& root = *parsed;
    if (const JsonNode* const errors = root.Get("errors"); errors != nullptr && !errors->items.empty()) {
      std::string error = errors->items.front().String("detail");
      if (error.empty()) {
        error = errors->items.front().String("title");
      }
      return std::unexpected(std::move(error));
    }
    const JsonNode* const data = root.Get("data");
    if (data == nullptr || data->kind != JsonNode::Kind::Array) {
      return std::unexpected("the answer has no maps");
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
      const JsonNode* const version =
        relationships != nullptr ? Included(root, relationships->Get("latestVersion")) : nullptr;
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
      if (
        const JsonNode* const author = relationships != nullptr ? Included(root, relationships->Get("author")) : nullptr
      ) {
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
    return {};
  }

  namespace
  {
    /** The editor's FAF sign-in: FAF's servers, the FAF client's id (the user's choice, 2026-11-10), no lobby scope. */
    online::FafEndpoints EditorEndpoints()
    {
      online::FafEndpoints endpoints;
      endpoints.oauthUrl = kFafOAuthUrl;
      endpoints.apiUrl = kFafApiUrl;
      endpoints.clientId = kFafClientId;
      endpoints.scopes = kFafScopes;
      endpoints.tokenDescription = "FAF map editor login";
      endpoints.approveWho = "the editor";
      return endpoints;
    }
  } // namespace

  EdFafSession::EdFafSession()
    : mAuth(EditorEndpoints())
  {
    mAuth.SetLog([](const char* const line) {
      FafLog("editor: %s", line);
    });
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

  void EdFafSession::Run(
    std::function<void()> job
  )
  {
    mThreads.emplace_back(std::move(job));
  }

  void EdFafSession::SetTokenFile(
    std::filesystem::path file
  )
  {
    mAuth.SetTokenFile(std::move(file));
  }

  void EdFafSession::Resume()
  {
    mAuth.Resume();
  }

  void EdFafSession::StartLogin()
  {
    mAuth.StartLogin();
  }

  void EdFafSession::Logout()
  {
    mAuth.Logout();
  }

  void EdFafSession::CancelLogin()
  {
    mAuth.CancelLogin();
  }

  std::string MapUploadBody(
    const std::string& boundary,
    const std::string& zipName,
    const std::string& zipBytes,
    const bool ranked
  )
  {
    std::string body;
    body.reserve(zipBytes.size() + 512U);
    body += "--" + boundary + "\r\n";
    body += "Content-Disposition: form-data; name=\"file\"; filename=\"" + zipName + "\"\r\n";
    body += "Content-Type: application/octet-stream\r\n\r\n";
    body += zipBytes;
    body += "\r\n--" + boundary + "\r\n";
    body += "Content-Disposition: form-data; name=\"metadata\"\r\n";
    body += "Content-Type: application/json\r\n\r\n";
    body += std::string("{\"isRanked\":") + (ranked ? "true" : "false") + "}";
    body += "\r\n--" + boundary + "--\r\n";
    return body;
  }

  EdFafSession::UploadState EdFafSession::Upload() const
  {
    std::lock_guard<std::mutex> lock(mLock);
    return mUpload;
  }

  void EdFafSession::UploadMap(
    std::filesystem::path zip,
    const bool ranked
  )
  {
    {
      std::lock_guard<std::mutex> lock(mLock);
      if (mUpload.running) {
        return;
      }
      if (mAuth.GetState() != State::LoggedIn) {
        mUpload = UploadState{false, true, false, "Sign in to FAF first (the start screen's FAF vault page)"};
        return;
      }
      mUpload = UploadState{true, false, false, "Uploading " + zip.filename().string() + "..."};
    }
    Run([this, zip, ranked] {
      std::string bytes;
      {
        std::ifstream in(zip, std::ios::binary);
        std::ostringstream all;
        all << in.rdbuf();
        bytes = all.str();
      }
      UploadState result{false, true, false, {}};
      if (bytes.empty()) {
        result.message = "Couldn't read " + zip.string();
      } else {
        // A boundary the zip doesn't hold (practically always the first).
        std::string boundary = "----FafEditorUpload7d3b";
        for (int n = 0; bytes.contains(boundary); ++n) {
          boundary = "----FafEditorUpload" + std::to_string(n) + "x9q";
        }
        for (int attempt = 0; attempt < 2; ++attempt) {
          platform::http::Call call;
          call.method = "POST";
          call.url = std::string(kFafApiUrl) + "/maps/upload";
          {
            std::lock_guard<std::mutex> lock(mLock);
            call.headers = "Accept: application/json\r\nAuthorization: Bearer " + mAuth.AccessToken() +
              "\r\nContent-Type: multipart/form-data; boundary=" + boundary + "\r\n";
          }
          call.body = MapUploadBody(boundary, zip.filename().string(), bytes, ranked);
          long status = 0;
          std::string body;
          if (const auto sent = platform::http::Request(call, status, body); !sent) {
            result.message = "The upload didn't reach FAF: " + sent.error();
            break;
          }
          if (status == 401 && attempt == 0 && mAuth.RefreshAccess()) {
            continue;
          }
          if (status >= 200 && status < 300) {
            result.ok = true;
            result.message = "Uploaded to the FAF vault: " + zip.filename().string();
          } else {
            std::string detail;
            if (const auto answer = ParseJson(body)) {
              if (const JsonNode* const errors = answer->Get("errors"); errors != nullptr && !errors->items.empty()) {
                detail = errors->items.front().String("detail");
                if (detail.empty()) {
                  detail = errors->items.front().String("title");
                }
              }
            } else {
              detail = answer.error();
            }
            result.message = "FAF's vault answered " + std::to_string(status) + (detail.empty() ? "" : ": " + detail);
          }
          break;
        }
      }
      std::lock_guard<std::mutex> lock(mLock);
      mUpload = result;
    });
  }

  void EdFafSession::Search(
    const VaultQuery& query,
    const int page
  )
  {
    if (mAuth.GetState() != State::LoggedIn || mSearching.exchange(true)) {
      return;
    }
    Run([this, query, page] {
      std::string error;
      std::vector<VaultMap> maps;
      int pages = 0;
      if (const auto fetched = FetchMaps(query, page, maps, pages); !fetched) {
        error = fetched.error();
      }
      {
        std::lock_guard<std::mutex> lock(mLock);
        mResults = std::move(maps);
        mPages = pages;
        mHaveResults = true;
      }
      mAuth.SetMessage(error.empty() ? std::string() : error);
      mSearching = false;
    });
  }

  void EdFafSession::SearchNamed(
    const std::string& name,
    const VaultQuery& query
  )
  {
    if (mAuth.GetState() != State::LoggedIn) {
      return;
    }
    {
      std::lock_guard<std::mutex> lock(mLock);
      mNamed[name] = Named{};
    }
    Run([this, name, query] {
      Named result;
      int pages = 0;
      if (const auto fetched = FetchMaps(query, 1, result.maps, pages); !fetched) {
        result.error = fetched.error();
      }
      result.done = true;
      std::lock_guard<std::mutex> lock(mLock);
      mNamed[name] = std::move(result);
    });
  }

  bool EdFafSession::NamedResults(
    const std::string& name,
    std::vector<VaultMap>& maps,
    std::string& error
  ) const
  {
    std::lock_guard<std::mutex> lock(mLock);
    const auto found = mNamed.find(name);
    if (found == mNamed.end() || !found->second.done) {
      return false;
    }
    maps = found->second.maps;
    error = found->second.error;
    return true;
  }

  bool EdFafSession::NamedAsked(
    const std::string& name
  ) const
  {
    std::lock_guard<std::mutex> lock(mLock);
    return mNamed.contains(name);
  }

  std::expected<void, std::string> EdFafSession::FetchMaps(
    const VaultQuery& query,
    const int page,
    std::vector<VaultMap>& maps,
    int& pages
  )
  {
    std::string error;
    {
      for (int attempt = 0; attempt < 2; ++attempt) {
        platform::http::Call call;
        call.url = VaultSearchUrl(query, page);
        {
          std::lock_guard<std::mutex> lock(mLock);
          call.headers = "Accept: application/vnd.api+json\r\nAuthorization: Bearer " + mAuth.AccessToken() + "\r\n";
        }
        long status = 0;
        std::string body;
        if (const auto sent = platform::http::Request(call, status, body); !sent) {
          error = sent.error();
          break;
        }
        if (status == 401 && attempt == 0) {
          // The access token lasts an hour: a new one from the refresh token, then the search again.
          if (const auto refreshed = mAuth.RefreshAccess(); !refreshed) {
            // A refused login signs out inside RefreshAccess; a server error keeps it for the next search.
            error = refreshed.error();
            break;
          }
          continue;
        }
        if (status != 200) {
          // The API says what it didn't take (a filter or an order it doesn't know).
          std::string detail;
          if (const auto answer = ParseJson(body)) {
            if (const JsonNode* const errors = answer->Get("errors"); errors != nullptr && !errors->items.empty()) {
              detail = errors->items.front().String("detail");
            }
          } else {
            detail = answer.error();
          }
          error = "FAF's map API answered " + std::to_string(status) + (detail.empty() ? "" : ": " + detail);
          break;
        }
        if (const auto read = ParseVaultSearch(body, maps, pages); !read) {
          error = read.error();
          break;
        }
        error.clear();
        break;
      }
    }
    if (!error.empty()) {
      return std::unexpected(std::move(error));
    }
    return {};
  }

  bool EdFafSession::TakeResults(
    std::vector<VaultMap>& maps,
    int& pages
  )
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

  std::string EdFafSession::Picture(
    const std::string& url
  )
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
          const std::string size = next.contains("/small/") ? "small" : "large";
          std::string body;
          const auto readFile = [&](const std::filesystem::path& path) {
            std::ifstream in(path, std::ios::binary);
            body.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
            return !body.empty();
          };
          char programData[MAX_PATH] = "";
          (void)::GetEnvironmentVariableA("ProgramData", programData, MAX_PATH);
          const std::filesystem::path client =
            std::filesystem::path(programData) / "FAForever" / "cache" / "maps" / size / file;
          const std::filesystem::path own =
            mPictureCache.empty() ? std::filesystem::path() : mPictureCache / size / file;
          bool ok = (programData[0] != '\0' && readFile(client)) || (!own.empty() && readFile(own));
          if (!ok) {
            platform::http::Call call;
            call.url = next;
            long status = 0;
            ok = platform::http::Request(call, status, body) && status == 200 && !body.empty();
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
