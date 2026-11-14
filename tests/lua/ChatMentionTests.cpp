#include "LuaTestSupport.h"

#include <filesystem>
#include <fstream>
#include <iterator>

namespace
{
  class ChatMention : public faf_lua_tests::LuaFixture
  {
  protected:
    std::string Source(const char* relative)
    {
      std::ifstream input(std::filesystem::path(FAF_CHAT_MENTION_DIR) / relative);
      EXPECT_TRUE(input.good()) << relative;
      return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    }

    void SetUp() override
    {
      Run(Source("modules/matching.lua"));
    }

    void Receiver()
    {
      Run(R"(
        matching = {Normalize=Normalize, Match=Match}
        saved, pushed, clock = nil, {}, 0
        function GetSystemTimeSeconds() return clock end
        function GetSessionClients() return {{name='Microchip', ['local']=true}} end
        function import(path)
          if string.find(path, 'matching.lua', 1, true) then return matching end
          if string.find(path, 'prefs.lua', 1, true) then
            return {GetFromCurrentProfile=function() return saved end,
                    SetToCurrentProfile=function(key, value) saved=value end}
          end
          return {Push=function(value) table.insert(pushed, value) end, Clear=function() pushed={} end}
        end
      )");
      Run(Source("modules/mentions.lua"));
    }
  };

  TEST_F(ChatMention, PlayerNameAndNicknamesMatchWithoutCase)
  {
    EXPECT_EQ(Str("return Match('MICROCHIP, need help!', 'Microchip', '')"), "Microchip");
    EXPECT_EQ(Str("return Match('@MC cover north', 'Microchip', ' chip, MC ; David')"), "MC");
    EXPECT_EQ(Str("return Match('Hi David!', '', 'David')"), "David");
    EXPECT_FALSE(Bool("return Match('normal chat', '', ', ;  ' )"));
  }

  TEST_F(ChatMention, NamesAreLiteralAndCannotMatchInsideOtherNames)
  {
    EXPECT_FALSE(Bool("return Match('microchip and chips and mc_2', '', 'chip,mc')"));
    EXPECT_EQ(Str("return Match('hello [MC]+!', '[MC]+', '')"), "[MC]+");
    EXPECT_FALSE(Bool("return Match('axb help', 'a.b', '')"));
    EXPECT_EQ(Str("return Match('Davidson no, David yes', 'David', '')"), "David");
  }

  TEST_F(ChatMention, DurationDefaultsAndBounds)
  {
    EXPECT_EQ(Num("return Normalize(nil).seconds"), 10);
    EXPECT_EQ(Num("return Normalize({seconds='15'}).seconds"), 15);
    EXPECT_EQ(Num("return Normalize({seconds=-2}).seconds"), 1);
    EXPECT_EQ(Num("return Normalize({seconds=999}).seconds"), 120);
    EXPECT_EQ(Num("return Normalize({seconds=0/0}).seconds"), 10);
    EXPECT_FALSE(Bool("return Normalize({enabled=false}).enabled"));
    EXPECT_EQ(Num("return Normalize({}).fontSize"), 17);
    EXPECT_EQ(Num("return Normalize({fontSize=99}).fontSize"), 32);
    EXPECT_EQ(Num("return Normalize({fontSize=2}).fontSize"), 12);
    EXPECT_FALSE(Bool("return Normalize({}).simulation"));
    EXPECT_FALSE(Bool("return Normalize({}).sound"));
  }

  TEST_F(ChatMention, IncomingMentionUsesSettingsAndDeduplicates)
  {
    Receiver();
    Run("Save({nicknames='MC',seconds=17}); Receive('Ally',{text='MC, help north!',to='allies',Id='1'},{});");
    EXPECT_EQ(Num("return table.getn(pushed)"), 1);
    EXPECT_EQ(Num("return pushed[1].seconds"), 17);
    EXPECT_EQ(Str("return pushed[1].sender .. ':' .. pushed[1].channel"), "Ally:ALLIES");
    Run("Receive('Ally',{text='MC, help north!',to='allies',Id='1'},{});");
    EXPECT_EQ(Num("return table.getn(pushed)"), 1);
    Run("Receive('Ally',{text='MC, help north!',to='allies',Id='2'},{});");
    EXPECT_EQ(Num("return table.getn(pushed)"), 2);
    EXPECT_EQ(Str("return saved.nicknames"), "MC");
  }

  TEST_F(ChatMention, SystemLinksAndDisabledMessagesDoNotNotify)
  {
    Receiver();
    Run(R"(
      Receive('Ally',{text='Microchip hello',to='notify'}, {})
      Receive('Ally',{text='Microchip hello'}, {Camera={}})
      Receive('Ally',{text='Microchip hello'}, {Type='ReceiveResources'})
      Save({enabled=false})
      Receive('Ally',{text='Microchip hello'}, {})
    )");
    EXPECT_EQ(Num("return table.getn(pushed)"), 0);
  }

  TEST_F(ChatMention, OwnPlayerNameAndNicknameCanTriggerMentions)
  {
    Receiver();
    Run("Save({nicknames='Micro'});Receive('Microchip',{text='Microchip hello',Id='own1'}, {})");
    Run("Receive('Microchip',{text='Micro hello',Id='own2'}, {})");
    EXPECT_EQ(Num("return table.getn(pushed)"), 2);
    EXPECT_EQ(Str("return pushed[1].sender"), "Microchip");
  }

  TEST_F(ChatMention, ObserverDoesNotUseWatchedArmiesName)
  {
    Receiver();
    Run("function GetSessionClients() return {{name='SomeoneElse'}} end; function GetFocusArmy() return 1 end");
    EXPECT_EQ(Str("return PlayerName()"), "");
    Run("Receive('Ally',{text='SomeoneElse help'}, {})");
    EXPECT_EQ(Num("return table.getn(pushed)"), 0);
  }

  TEST_F(ChatMention, ControllerHookRespectsMuteAndKeepsNormalChat)
  {
    Receiver();
    Run(R"(
      mentionModule = {Receive=Receive}
      local oldImport = import
      function import(path)
        if string.find(path,'mentions.lua',1,true) then return mentionModule end
        return oldImport(path)
      end
      visible, appends = true, 0
      function IsValidEntry(entry) return visible end
      function AppendEntry(entry) appends=appends+1 end
      function OnReceive(sender,message) AppendEntry({Text=message.text}) end
    )");
    Run(Source("hook/lua/ui/game/chat/ChatController.lua"));
    Run("visible=false; OnReceive('Ally',{text='Microchip help',Id='muted'})");
    EXPECT_EQ(Num("return table.getn(pushed)"), 0);
    EXPECT_EQ(Num("return appends"), 1);
    Run("visible=true; OnReceive('Ally',{text='Microchip help',Id='visible'})");
    EXPECT_EQ(Num("return table.getn(pushed)"), 1);
    Run("AppendEntry({Text='Microchip outgoing echo'})");
    EXPECT_EQ(Num("return table.getn(pushed)"), 1);
    EXPECT_EQ(Num("return appends"), 3);
  }

  TEST_F(ChatMention, EveryModFileCompilesInTheGameLuaParser)
  {
    for (const auto& entry : std::filesystem::recursive_directory_iterator(FAF_CHAT_MENTION_DIR)) {
      if (entry.path().extension() != ".lua") continue;
      std::ifstream input(entry.path());
      const std::string source{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
      std::string error;
      EXPECT_EQ(Load(source, &error), 0) << entry.path() << ": " << error;
    }
  }

  TEST_F(ChatMention, LocalOutgoingEchoTriggersExactlyOneMention)
  {
    Receiver();
    Run(R"(
      mentionModule = {Receive=Receive}
      local oldImport=import
      function import(path)
        if string.find(path,'mentions.lua',1,true) then return mentionModule end
        return oldImport(path)
      end
      function GetArmiesTable() return {armiesTable={{nickname='Microchip'}}} end
      function IsValidEntry() return true end
      function AppendEntry() end
      function OnReceive(sender,message)
        AppendEntry({ArmyID=1,Text=message.text,Recipient=message.to,Id=message.Id})
      end
    )");
    Run(Source("hook/lua/ui/game/chat/ChatController.lua"));
    Run("AppendEntry({ArmyID=1,Text='Microchip testing',Recipient=2,Id='echo'})");
    EXPECT_EQ(Num("return table.getn(pushed)"), 1);
    EXPECT_EQ(Str("return pushed[1].channel"), "PRIVATE");
    Run("OnReceive('Microchip',{text='Microchip testing',to=2,Id='echo'})");
    EXPECT_EQ(Num("return table.getn(pushed)"), 1);
  }

  TEST_F(ChatMention, PopupTimerQueueAndCloseUseRealTime)
  {
    Run(R"(
      clock, groups, controls, soundCount = 0, {}, {}, 0
      function Sound(value) return value end
      function PlaySound(value) soundCount=soundCount+1 end
      function WARN(value) warnings=(warnings or 0)+1 end
      function property(value)
        local p = {value=value or 0}
        function p:Set(value) self.value=value end
        return setmetatable(p,{__call=function(self) return self.value end})
      end
      function control()
        local c = {Width=property(1120),Height=property(630),Top=property(),Depth=property()}
        function c:SetSolidColor(value) self.color=value end
        function c:SetColor(value) end
        function c:SetText(value) self.text=value end
        function c:DisableHitTest() end
        function c:Destroy() self.destroyed=true end
        function c:SetNeedsFrameUpdate(value) self.updating=value end
        function c:SetAlpha(value, children) self.alpha=value end
        function c:GetTopmostDepth() return 10 end
        function c:GetStringAdvance(value) return string.len(value)*8 end
        table.insert(controls,c)
        return c
      end
      frame=control()
      function GetFrame() return frame end
      function GetSystemTimeSeconds() return clock end
      function IsDestroyed(c) return c.destroyed end
      function import(path)
        if string.find(path,'uiutil.lua',1,true) then
          return {CreateText=function(parent,text,size) local c=control();c.text=text;c.fontSize=size;return c end}
        elseif string.find(path,'layouthelpers.lua',1,true) then
          return {ScaleNumber=function(n) return n end, AtHorizontalCenterIn=function() end,
                  AtLeftTopIn=function() end,AtCenterIn=function() end}
        elseif string.find(path,'group.lua',1,true) then
          return {Group=function() local c=control();table.insert(groups,c);return c end}
        elseif string.find(path,'bitmap.lua',1,true) then return {Bitmap=control}
        else return {WrapText=function(text) return {text} end} end
      end
    )");
    Run(Source("modules/popup.lua"));
    Run(R"(
      Push({sender='Ally',channel='ALLIES',text='Microchip help',seconds=10,fontSize=24,sound=true})
      Push({sender='Ally',channel='ALLIES',text='Microchip again',seconds=3})
    )");
    EXPECT_EQ(Num("return groups[1].alpha"), 0);
    Run("clock=0.18;groups[1]:OnFrame(0)");
    EXPECT_GT(Num("return groups[1].alpha"), 0);
    EXPECT_LT(Num("return groups[1].alpha"), 1);
    Run(R"(
      clock=10.27;groups[1]:OnFrame(0)
    )");
    EXPECT_FALSE(Bool("return groups[1].destroyed or false"));
    EXPECT_EQ(Num("return table.getn(groups)"), 1);
    EXPECT_EQ(Num("return soundCount"), 1);
    EXPECT_EQ(Num("for _,c in ipairs(controls) do if c.text=='Microchip help' then return c.fontSize end end"), 24);
    EXPECT_EQ(Num("return groups[1].alpha"), 1);
    Run("clock=10.37;groups[1]:OnFrame(0);clock=10.48;groups[1]:OnFrame(0)");
    EXPECT_GT(Num("return groups[1].alpha"), 0);
    EXPECT_LT(Num("return groups[1].alpha"), 1);
    EXPECT_FALSE(Bool("return groups[1].destroyed or false"));
    Run("clock=10.60;groups[1]:OnFrame(0)");
    EXPECT_TRUE(Bool("return groups[1].destroyed"));
    EXPECT_EQ(Num("return table.getn(groups)"), 2);
    EXPECT_EQ(Num("return soundCount"), 1);
    Run(R"(
      for _,c in ipairs(controls) do
        if c.color=='ff1d2b3b' and not c.destroyed then close=c end
      end
      close:HandleEvent({Type='ButtonPress'})
      clock=clock+0.23;groups[2]:OnFrame(0)
    )");
    EXPECT_TRUE(Bool("return groups[2].destroyed"));
    Run(R"(
      Push({sender='Ally',text='old preview',seconds=10,fontSize=17})
      Push({sender='Ally',text='queued old preview',seconds=10,fontSize=17})
      Preview({sender='Ally',text='new font preview',seconds=10,fontSize=32})
    )");
    EXPECT_TRUE(Bool("return groups[3].destroyed"));
    EXPECT_EQ(Num("return table.getn(groups)"), 4);
    EXPECT_EQ(Num("for _,c in ipairs(controls) do if c.text=='new font preview' then return c.fontSize end end"), 32);
    Run(R"(
      function PlaySound() error('Audio unavailable') end
      Preview({sender='Ally',text='silent fallback',seconds=10,fontSize=20,sound=true})
    )");
    EXPECT_TRUE(Bool("return groups[4].destroyed"));
    EXPECT_FALSE(Bool("return groups[5].destroyed or false"));
    EXPECT_EQ(Num("return warnings"), 1);
  }

  TEST_F(ChatMention, OptionsFontStepsPreviewImmediatelyAndSavePersistsSize)
  {
    Receiver();
    Run(R"(
      local mention={Settings=Settings,Save=Save,PlayerName=PlayerName}
      edits,buttons,previews={}, {}, {}
      local function property() return {Set=function() end} end
      local function control()
        local c={Width=property(),Height=property()}
        function c:SetSolidColor() end
        function c:SetColor() end
        function c:DisableHitTest() end
        function c:SetFont(face,size) self.fontSize=size end
        function c:SetText(value)
          self.text=value
          if self.OnTextChanged then self:OnTextChanged(value) end
        end
        function c:GetText() return self.text end
        return c
      end
      function GetFrame() return {} end
      function IsDestroyed() return false end
      function import(path)
        if path=='/mods/Microchip-Chat-Mention/modules/mentions.lua' then return mention
        elseif path=='/mods/Microchip-Chat-Mention/modules/popup.lua' then
          return {Preview=function(value) table.insert(previews,value) end}
        elseif string.find(path,'uiutil.lua',1,true) then return {
          CreateText=function(parent,value,size)
            local c=control();c.text=value;c.fontSize=size
            if value=='+' then fontPlus=parent end
            if value=='Aa - message text preview' then sample=c end
            return c
          end,
          SetupEditStd=function() end,
          CreateButtonWithDropshadow=function(parent,path,label)
            local c=control();buttons[label]=c;return c
          end
        }
        elseif string.find(path,'layouthelpers.lua',1,true) then
          return {ScaleNumber=function(n) return n end,AtLeftTopIn=function() end,
                  AtCenterIn=function() end,FillParent=function() end}
        elseif string.find(path,'group.lua',1,true) then return {Group=control}
        elseif string.find(path,'bitmap.lua',1,true) then return {Bitmap=control}
        elseif string.find(path,'edit.lua',1,true) then
          return {Edit=function() local c=control();table.insert(edits,c);return c end}
        else return {Popup=function()
          return {OnClosed=function() end,Close=function(self) self:OnClosed() end}
        end} end
      end
    )");
    Run(Source("modules/options.lua"));
    Run("Open();edits[3]:SetText('28')");
    EXPECT_EQ(Num("return sample.fontSize"), 28);
    Run("fontPlus:HandleEvent({Type='ButtonPress'})");
    EXPECT_EQ(Str("return edits[3]:GetText()"), "29");
    EXPECT_EQ(Num("return previews[1].fontSize"), 29);
    Run("buttons['Test Popup']:OnClick();buttons.Save:OnClick()");
    EXPECT_EQ(Num("return table.getn(previews)"), 2);
    EXPECT_EQ(Num("return saved.fontSize"), 29);
  }

  TEST_F(ChatMention, SimulationGeneratesOnlyLocalMessagesEveryTenSeconds)
  {
    Receiver();
    Run(R"(
      local previousImport=import
      function import(path)
        if string.find(path,'group.lua',1,true) then
          return {Group=function()
            timer={DisableHitTest=function() end,SetNeedsFrameUpdate=function() end,
                   Destroy=function(self) self.destroyed=true end}
            return timer
          end}
        end
        return previousImport(path)
      end
      local function property()
        return {Set=function(self,value) self.value=value end}
      end
      function GetFrame() return {Left=function() return 0 end,Top=function() return 0 end} end
      function IsDestroyed(value) return value.destroyed end
      function SessionSendChatMessage() error('Test traffic must never reach the network') end
      local oldImport=import
      function import(path)
        local module=oldImport(path)
        if string.find(path,'group.lua',1,true) then
          local create=module.Group
          module.Group=function()
            local value=create()
            value.Width=property();value.Height=property();value.Left=property();value.Top=property()
            return value
          end
        end
        return module
      end
      Save({simulation=true,sound=true,fontSize=24,seconds=15})
      Start()
      clock=0;timer:OnFrame()
      clock=9.9;timer:OnFrame()
    )");
    EXPECT_EQ(Num("return table.getn(pushed)"), 0);
    EXPECT_EQ(Num("return timer.Width.value"), 1);
    EXPECT_EQ(Num("return timer.Height.value"), 1);
    Run("clock=10;timer:OnFrame()");
    EXPECT_EQ(Num("return table.getn(pushed)"), 1);
    EXPECT_EQ(Str("return pushed[1].channel"), "LOCAL TEST");
    EXPECT_EQ(Num("return pushed[1].fontSize"), 24);
    EXPECT_EQ(Num("return pushed[1].seconds"), 15);
    EXPECT_TRUE(Bool("return pushed[1].sound"));
    Run("clock=20;timer:OnFrame();Save({simulation=false});clock=40;timer:OnFrame()");
    EXPECT_EQ(Num("return table.getn(pushed)"), 2);
  }
}
