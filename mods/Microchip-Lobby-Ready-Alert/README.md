# Microchip Lobby Ready Alert

Copy the `Microchip-Lobby-Ready-Alert` folder to your FAF user `mods` directory, enable the mod in FAF, and open a new multiplayer lobby. Use a Windows faf-re build that includes the lobby ready alert hook and `SC_FlashGameWindow` command.

When all seated human players, including you if you have a slot, are Ready, the game plays an incoming-transmission sound and flashes the Windows title bar and taskbar button. Empty slots, AI and observers are ignored. The alert fires once each time the lobby becomes fully ready.
