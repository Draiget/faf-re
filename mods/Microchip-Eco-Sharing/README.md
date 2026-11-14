# Microchip Eco Sharing

UI-only mod by Microchip. Works with classic FAF and faf-re. Only the giver needs it.

Preserves the installed original red metal frame, resource icons, lime sliders
and checked buttons.

Open **ECO** in the top-left controls. Set separate energy and mass reserve percentages,
tick recipients for each resource, enable automatic sharing, then click **Apply**.
Automatic sharing starts disabled; reserves default to 75% energy and 60% mass.
Closing the panel without Apply leaves the active settings unchanged.

- **Equal:** divide the available surplus equally between selected empty allies;
  redistribute portions that a receiver cannot store.
- **Rank:** fill selected empty allies in highest-FAF-rating order. Unrated players
  follow rated players, with army slot as the tie-breaker.
- **Arrows:** override the order. **Reset to rank** restores the FAF-rating order,
  preserving reserve percentages and resource selections.

It uses the same visible allied storage information as the scoreboard and the
normal `GiveResourcesToPlayer` callback. It does not read hidden enemy economies
or install simulation code. Receivers with missing/stale data are skipped.
Tick **Energy** and/or **Mass** beside at least one ally: enabling sharing alone
does not select recipients. Apply stays open with a warning if none are selected.

Sharing rounds happen no faster than every three real seconds and three game
seconds, even at faster game speeds. Each round can send to several allies.
One allies-chat message announces the approximate total being sent and the
recipient (or recipient count). Normal FAF receipts report exact amounts received.
There is also a three-game-second cooldown per recipient/resource; pauses, observers and
replays do not trigger transfers. Empty means at most one stored resource unit.
Reserves are checked against the latest available economy data; normal spending
and other transfers can still change storage before a queued gift is processed.
Normal FAF resource-transfer notifications still apply.

The menu frame expands to contain all overlay buttons and their dropdown arrows,
including the separate Microchip Team Colour Bands button.

To install manually, extract the **Microchip-Eco-Sharing** folder into your FAF
Mods folder and enable **Microchip Eco Sharing** in UI Mod Manager. Restart the game.
