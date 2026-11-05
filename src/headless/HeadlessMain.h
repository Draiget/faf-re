#pragma once

/**
 * The replay player: headless's whole program, and the game's too when started with `/replaykeyframes`,
 * which is how the replay viewer's hidden process writes keyframes this same exe can load.
 */
int HEADLESS_Main(int argc, char** argv);
