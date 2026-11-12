// Desync telemetry's local parts (src/moho/sim/DesyncTelemetry.cpp): the dump scrubber, the JSON string escaper, the
// OTLP attribute builder and the on/off switches. Nothing here sends: TELEMETRY_Send is never called, and the switches
// are put back after each test (the default endpoint is the live faf-re desync server).

#include <string>
#include <gtest/gtest.h>

#include "gpg/core/containers/String.h"
#include "moho/sim/DesyncTelemetry.h"

namespace
{
  // Saves and restores the telemetry switches a test changes.
  class TelemetrySwitches : public ::testing::Test
  {
  protected:
    void SetUp() override
    {
      mEnabled = moho::telemetry_Enabled;
      mEndpoint = moho::telemetry_Endpoint.c_str();
      mToken = moho::telemetry_Token.c_str();
      mDump = moho::telemetry_DumpEndpoint.c_str();
    }

    void TearDown() override
    {
      moho::telemetry_Enabled = mEnabled;
      moho::telemetry_Endpoint = fa::string(mEndpoint.c_str());
      moho::telemetry_Token = fa::string(mToken.c_str());
      moho::telemetry_DumpEndpoint = fa::string(mDump.c_str());
    }

  private:
    bool mEnabled = false;
    std::string mEndpoint;
    std::string mToken;
    std::string mDump;
  };

  std::string Scrubbed(
    std::string text
  )
  {
    moho::TELEMETRY_Scrub(text);
    return text;
  }
} // namespace

TEST(
  Telemetry,
  JsonStringEscapesQuotesBackslashesAndControls
)
{
  EXPECT_EQ(moho::TELEMETRY_JsonString("plain"), "\"plain\"");
  EXPECT_EQ(moho::TELEMETRY_JsonString("a\"b\\c"), "\"a\\\"b\\\\c\"");
  EXPECT_EQ(moho::TELEMETRY_JsonString("l1\nl2\r\tx"), "\"l1\\nl2\\r\\tx\"");
  EXPECT_EQ(moho::TELEMETRY_JsonString(std::string("\x01\x1f", 2)), "\"\\u0001\\u001f\"");
  EXPECT_EQ(moho::TELEMETRY_JsonString(""), "\"\"");
}

TEST(
  Telemetry,
  AttributesBuildOtlpItems
)
{
  moho::CTelemetryAttributes attributes;
  EXPECT_TRUE(attributes.Json().empty());
  attributes.Add("map", std::string("setons \"clutch\""));
  attributes.Add("beat", static_cast<std::int64_t>(1500));
  attributes.AddBool("ranked", true);
  attributes.AddBool("rejoined", false);
  attributes.AddDouble("ratio", 0.5);
  EXPECT_EQ(
    attributes.Json(),
    "{\"key\":\"map\",\"value\":{\"stringValue\":\"setons \\\"clutch\\\"\"}},"
    "{\"key\":\"beat\",\"value\":{\"intValue\":\"1500\"}},"
    "{\"key\":\"ranked\",\"value\":{\"boolValue\":true}},"
    "{\"key\":\"rejoined\",\"value\":{\"boolValue\":false}},"
    "{\"key\":\"ratio\",\"value\":{\"doubleValue\":0.5}}"
  );
}

TEST_F(
  TelemetrySwitches,
  ScrubMasksTheTokenAndUserFolders
)
{
  moho::telemetry_Token = fa::string("s3cret-token");
  EXPECT_EQ(
    Scrubbed("Authorization: Bearer s3cret-token; again s3cret-token"), "Authorization: Bearer <token>; again <token>"
  );
  EXPECT_EQ(Scrubbed("C:\\Users\\Alice\\Documents\\x.log"), "C:\\Users\\<user>\\Documents\\x.log");
  EXPECT_EQ(Scrubbed("c:/users/bob/x"), "c:/users/<user>/x");
  EXPECT_EQ(Scrubbed("/home/carol/.faf/game.log"), "/home/<user>/.faf/game.log");
  EXPECT_EQ(Scrubbed("'C:\\USERS\\Dave' and \"/home/eve\""), "'C:\\USERS\\<user>' and \"/home/<user>\"");
  // A folder name that ends the text, and one that is empty, stay as they are around the mask.
  EXPECT_EQ(Scrubbed("/home/frank"), "/home/<user>");
  EXPECT_EQ(Scrubbed("/home//x"), "/home//x");
  EXPECT_EQ(Scrubbed("no paths here"), "no paths here");

  moho::telemetry_Token = fa::string("");
  EXPECT_EQ(Scrubbed("token s3cret-token"), "token s3cret-token");
}

TEST_F(
  TelemetrySwitches,
  OnOnlyWithAnEndpointAndDumpsOnlyWithADumpEndpoint
)
{
  moho::telemetry_Enabled = false;
  moho::telemetry_Endpoint = fa::string("http://127.0.0.1:9");
  moho::telemetry_DumpEndpoint = fa::string("http://127.0.0.1:9/dumps");
  EXPECT_FALSE(moho::TELEMETRY_IsOn());
  EXPECT_FALSE(moho::TELEMETRY_DumpUploadOn());

  moho::telemetry_Enabled = true;
  EXPECT_TRUE(moho::TELEMETRY_IsOn());
  EXPECT_TRUE(moho::TELEMETRY_DumpUploadOn());

  moho::telemetry_DumpEndpoint = fa::string("");
  EXPECT_TRUE(moho::TELEMETRY_IsOn());
  EXPECT_FALSE(moho::TELEMETRY_DumpUploadOn());

  moho::telemetry_Endpoint = fa::string("");
  EXPECT_FALSE(moho::TELEMETRY_IsOn());
  EXPECT_FALSE(moho::TELEMETRY_DumpUploadOn());
}
