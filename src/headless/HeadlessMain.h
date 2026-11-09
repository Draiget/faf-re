#pragma once

/**
 * The replay player: headless's whole program, and the game's too when started with `/replaykeyframes`,
 * which is how the replay viewer's hidden process writes keyframes this same exe can load.
 */
int HEADLESS_Main(int argc, char** argv);

// Engine addition (replay timeline): set in the game's exe (GameEntry.cpp), and read by its WinMain, for `/replaykeyframes`.
// The engine library holds WinMain and not the player, so its other users link without the player.
extern int (*gGameReplayPlayerMain)(int argc, char** argv);
