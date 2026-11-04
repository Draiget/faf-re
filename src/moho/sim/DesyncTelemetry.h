#pragma once

#include <cstdint>
#include <string>

#include "legacy/containers/String.h"

namespace moho
{
  /**
   * Engine addition (issues #218, #219): desync telemetry, on by default and sent to the faf-re
   * desync server (`kTelemetryDefaultHost`); `/notelemetry` or `telemetry_Enabled 0` turns it off.
   * Only live multiplayer games send: one `faf.desync` log record per player whose hash differed
   * from ours at the first desync, and one `faf.game.end` record at the game's end, as OTLP/HTTP
   * JSON to `telemetry_Endpoint` (+ `/v1/logs`). Off, nothing starts: no thread, no file, no
   * connection.
   */
  extern bool telemetry_Enabled;

  /// The faf-re desync server, behind Cloudflare. The Windows build posts `https://`; the Linux
  /// build has no TLS library and posts plain `http://`, which the server also accepts.
  inline constexpr const char kTelemetryDefaultHost[] = "fafre-metrics.draiget.dev";

  /// Collector base URL, `http://host:port` or `https://host` (`/telemetryendpoint URL`).
  extern msvc8::string telemetry_Endpoint;

  /// Ingest token sent as `Authorization: Bearer <token>` when set (`/telemetrytoken T`). The
  /// default ships with every build, so it only keeps casual junk out; reading needs another one.
  extern msvc8::string telemetry_Token;

  /**
   * Where the recorder's dump goes, as a `.tar.gz` POSTed to this URL as given
   * (`/telemetrydumpendpoint URL`; default the desync server's `/dumps`). Empty uploads nothing.
   * Unlike the records, the dump holds player names and the sync log; the token and user folder
   * names are masked (`TELEMETRY_Scrub`).
   */
  extern msvc8::string telemetry_DumpEndpoint;

  /// One log record's attributes, built as OTLP JSON (`{"key": ..., "value": {...}}` items).
  class CTelemetryAttributes
  {
  public:
    void Add(const char* key, const std::string& value);
    void Add(const char* key, std::int64_t value);
    void AddBool(const char* key, bool value);
    void AddDouble(const char* key, double value);

    [[nodiscard]] const std::string& Json() const noexcept
    {
      return mJson;
    }

  private:
    void Key(const char* key);

    std::string mJson;
  };

  /**
   * Reads the startup flags and, when telemetry is on, retries what an earlier session left in
   * the outbox. Call once at startup, before `/con` runs, so the switch values it notes for
   * `faf.switches.changed` are the defaults.
   */
  void TELEMETRY_Startup();

  /// Whether records are sent: `telemetry_Enabled` with an endpoint set.
  [[nodiscard]] bool TELEMETRY_IsOn();

  /// Whether dumps are uploaded: records are sent and `telemetry_DumpEndpoint` is set.
  [[nodiscard]] bool TELEMETRY_DumpUploadOn();

  /**
   * Queues the file at `path` (a packed dump) for upload to `telemetry_DumpEndpoint`, through
   * the same outbox and attempts as a record. The file is deleted once it is sent or dropped.
   */
  void TELEMETRY_SendFile(const std::string& path);

  /// Masks what a dump must not carry off the machine: the ingest token, and the user's folder
  /// name in `...\Users\<name>\...` and `/home/<name>/` paths.
  void TELEMETRY_Scrub(std::string& text);

  /**
   * Queues one log record (`eventName`, OTLP severity number and text, attributes) for the
   * sender thread, which writes it to the outbox file and posts it. Any thread; never blocks on
   * the network. On failure the record stays in the outbox and is retried with the next record
   * and at the next start, at most three attempts in all.
   */
  void TELEMETRY_Send(const char* eventName, int severityNumber, const char* severityText, const CTelemetryAttributes& attributes);

  /**
   * Waits up to `timeoutMs` until every queued record had its attempt, so the game-end record is
   * posted before the process exits. Returns at once when nothing was queued. On a timeout the
   * sender stops until the next record: no more posts, outbox writes or log lines while a quit
   * tears the process down; the outbox file keeps the records for the next start.
   */
  void TELEMETRY_WaitIdle(int timeoutMs);

  /// JSON string literal for `text`, quotes included.
  [[nodiscard]] std::string TELEMETRY_JsonString(const std::string& text);
} // namespace moho
