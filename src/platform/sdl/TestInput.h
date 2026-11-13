#pragma once

// Engine addition: scripted input for test runs (`/testinput <file>`). The script's keys, text, mouse
// actions and window requests are pushed into SDL's event queue, so they take the path the window
// system's own input takes (translation, the developer windows' Dear ImGui, the shell's focus
// rules) without the desktop's keyboard, mouse or foreground window. The step list is in
// TestInput.cpp.

namespace platform::window::test
{
  // Runs a console command for a `con` step.
  using CommandRunner = void (*)(const char* utf8Command);

  // Reads the script at `utf8Path`; false when it can't be read. Main thread.
  bool Start(const char* utf8Path, CommandRunner runCommand);
  [[nodiscard]] bool IsActive();

  // Runs the steps that are due. Once a frame, on the main thread.
  void Tick();

  // A line the engine logged, for `waitlog` steps. Any thread.
  void NoteLogLine(const char* utf8Line);
} // namespace platform::window::test

namespace platform::window::sdl
{
  // WindowSdl.cpp, for the script: the SDL key code and scan code a Windows virtual-key code comes
  // from on this keyboard layout; false when no key gives it.
  [[nodiscard]] bool KeyOfVirtualKey(int virtualKey, unsigned int& keycode, int& scancode);
  // The next PickFolder answers this without showing the system's dialog: the folder, or a cancel.
  void AnswerNextFolderPick(bool chosen, const char* utf8Path);
} // namespace platform::window::sdl
