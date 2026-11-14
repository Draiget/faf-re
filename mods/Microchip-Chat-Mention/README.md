# Microchip Chat Mention

UI-only mod for the current FAF ChatController. It watches your actual local player name and optional extra nicknames. Mentions match literal whole names without caring about ASCII case, so `chip` does not match `microchip`. Non-ASCII names match literally; Unicode case folding is not provided.

The sender and original message slide down below the top HUD. Each popup stays for **10 seconds** by default, with a countdown, shrinking timer bar and corner **X**. The timer uses real time, including while the simulation is paused. Up to five additional mentions queue behind the current popup; a larger burst drops the oldest waiting message.

Opening uses a 0.36-second slide and fade with a gentle settle. Closing uses a 0.22-second upward slide and fade, for both expiry and the X button. The display timer starts after the entrance, and closing during the entrance continues smoothly from the current position.

Enable the mod in the FAF mod manager. Open **UI Mods Options > Microchip Chat Mention** (UI Mod Tools), or press **Ctrl+Shift+M** without UI Mod Tools. Enter comma-separated nicknames and a duration of **1–120 seconds**, then Save. Settings persist in your current player profile. Duration changes apply to future mentions. Test Popup previews the draft duration without saving it.

The options also include **Simulation mode**, which generates a local test mention every 10 real seconds while in game, **Play notification sound**, and **Message font size** (12–32; default 17). Simulation and sound are off by default. Save to apply changes. Simulation messages never leave your computer; turning off mentions clears queued popups and pauses simulation. The game's incoming-transmission cue (`Interface/UI_Comm_UEF_In`) plays once when each popup opens, including queued and test popups.

Use the font-size **− / +** controls or type a size. The sample text updates live, and the step controls immediately preview the new size. **Test Popup** replaces the current popup and clears waiting previews so repeated tests never wait behind old messages. **Save** keeps the chosen size for subsequent mentions. A sound failure cannot hide the popup.

Chat already accepted by FAF is eligible, including your own messages and locally echoed outgoing private messages. Muted messages, system notifications and camera/location links do not trigger popups. This mod does not send chat or change the simulation. It chains the same ChatController hooks as Microchip Offline Chat Translation.

Extract the distributed ZIP into your FAF user `mods` directory, keeping the `Microchip-Chat-Mention` folder intact. Restart the game after enabling the mod. The GIF is an illustrative mockup, not captured gameplay.
