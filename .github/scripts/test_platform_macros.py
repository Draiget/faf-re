"""Tests for platform_macros.py: python -m unittest discover -s .github/scripts -p "test_*.py"."""
import unittest

import platform_macros as checker


class CheckLine(unittest.TestCase):
    def refused(self, line):
        return checker.check_line(line) is not None

    def test_compiler_macros_are_refused(self):
        for line in ("#ifdef _WIN32", "#ifndef _WIN32", "#if defined(_WIN64)", "#  elif defined(__APPLE__)",
                     "#if defined(__linux__) && defined(__x86_64__)", "#elifdef __unix__", "#if __linux"):
            with self.subTest(line=line):
                self.assertTrue(self.refused(line))

    def test_a_comment_does_not_excuse_a_compiler_macro(self):
        self.assertTrue(self.refused("#ifdef _WIN32 // old code"))

    def test_a_compiler_macro_inside_the_comment_is_not_a_test(self):
        self.assertFalse(self.refused("#if FAFRE_PLATFORM_WINDOWS // was _WIN32"))

    def test_one_posix_system_needs_a_comment(self):
        self.assertTrue(self.refused("#if FAFRE_PLATFORM_LINUX"))
        self.assertTrue(self.refused("#elif FAFRE_PLATFORM_MACOS"))
        self.assertTrue(self.refused("#if !FAFRE_PLATFORM_LINUX"))
        self.assertFalse(self.refused("#if FAFRE_PLATFORM_LINUX // MSG_NOSIGNAL"))
        self.assertFalse(self.refused("#if FAFRE_PLATFORM_MACOS /* Mach ports */"))

    def test_an_empty_comment_is_no_reason(self):
        self.assertTrue(self.refused("#if FAFRE_PLATFORM_LINUX //"))

    def test_our_macros_pass(self):
        for line in ("#if FAFRE_PLATFORM_WINDOWS", "#if !FAFRE_PLATFORM_WINDOWS", "#if FAFRE_PLATFORM_POSIX",
                     "#elif FAFRE_PLATFORM_POSIX && defined(__x86_64__)"):
            with self.subTest(line=line):
                self.assertFalse(self.refused(line))

    def test_lines_that_are_not_tests_pass(self):
        for line in ("#endif // FAFRE_PLATFORM_LINUX", "#else // _WIN32", "// #ifdef _WIN32",
                     "#define FAFRE_PLATFORM_LINUX 1", "#include <windows.h>", "int _WIN32_value = 0;"):
            with self.subTest(line=line):
                self.assertFalse(self.refused(line))

    def test_check_text_reports_line_numbers(self):
        problems = checker.check_text("int a;\n#ifdef _WIN32\n#endif\n#if FAFRE_PLATFORM_LINUX\n#endif\n")
        self.assertEqual([number for number, _ in problems], [2, 4])


class AppliesTo(unittest.TestCase):
    def test_code_under_src_tests_tools(self):
        self.assertTrue(checker.applies_to("src/moho/app/WinApp.cpp"))
        self.assertTrue(checker.applies_to("tests/linux/Win32ShimHandleTests.cpp"))
        self.assertTrue(checker.applies_to("tools/difffuzz/src/dump_main.cpp"))
        self.assertTrue(checker.applies_to("src\\platform\\posix\\NetPosix.cpp"))

    def test_skipped_files(self):
        self.assertFalse(checker.applies_to("src/platform/PlatformDefines.h"))
        self.assertFalse(checker.applies_to("tests/particles/upload_host/ParticleUploadTests.cpp"))
        self.assertFalse(checker.applies_to("dependencies/SDL3/src/SDL.c"))
        self.assertFalse(checker.applies_to("src/sim_sources.cmake"))


if __name__ == "__main__":
    unittest.main()
