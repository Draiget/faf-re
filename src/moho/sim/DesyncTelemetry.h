#pragma once

#include <cstdint>
#include <string>

#include "legacy/containers/String.h"

namespace moho
{
  /**
   * Engine addition (issue #218): opt-in desync telemetry. Off by default; `/telemetry` or
   * `telemetry_Enabled 1` turns it on. With it on, a multiplayer game sends one `faf.desync` log
   * record per player whose hash differed from ours at the first desync, and one `faf.game.end`
   * record at its end, as OTLP/HTTP JSON to `telemetry_Endpoint` (+ `/v1/logs`). Off, nothing
   * starts: no thread, no file, no connection.
   */
  extern bool telemetry_Enabled;

  /// Collector base URL, `http://host:port` or `https://host` (`/telemetryendpoint URL`).
  extern msvc8::string telemetry_Endpoint;

  /// Ingest token sent as `Authorization: Bearer <token>` when set (`/telemetrytoken T`).
  extern msvc8::string telemetry_Token;

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

  /**
   * Queues one log record (`eventName`, OTLP severity number and text, attributes) for the
   * sender thread, which writes it to the outbox file and posts it. Any thread; never blocks on
   * the network. On failure the record stays in the outbox and is retried with the next record
   * and at the next start, at most three attempts in all.
   */
  void TELEMETRY_Send(const char* eventName, int severityNumber, const char* severityText, const CTelemetryAttributes& attributes);

  /**
   * Waits up to `timeoutMs` until every queued record had its attempt, so the game-end record is
   * posted before the process exits. Returns at once when nothing was queued.
   */
  void TELEMETRY_WaitIdle(int timeoutMs);

  /// JSON string literal for `text`, quotes included.
  [[nodiscard]] std::string TELEMETRY_JsonString(const std::string& text);
} // namespace moho
