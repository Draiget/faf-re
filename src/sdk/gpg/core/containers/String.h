#pragma once

#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

namespace gpg
{
	using StrArg = const char*;
	using WStrArg = const wchar_t*;

	static msvc8::string sWhitespaceChars{ " \n\t\r" }; // 0x00F32308

	int STR_Utf8ByteOffset(StrArg str, int pos); // 0x009380A0
	int STR_Utf8Len(char const*); // 0x00938070
	const char* STR_NextUtf8Char(const char* str); // 0x00938040
	const char* STR_PreviousUtf8Char(const char* str, const char* start); // 0x00938020
	msvc8::string STR_Utf8SubString(StrArg str, int pos, int len); // 0x009387D0
	char* STR_EncodeUtf8Char(char*, wchar_t, const char*); // 0x00937F90
	const char* STR_DecodeUtf8Char(const char*, wchar_t&); // 0x00937EF0
	msvc8::string STR_WideToUtf8(const wchar_t*); // 0x00938680
	std::wstring STR_Utf8ToWide(StrArg str); // 0x00938720

	bool STR_GetToken(const char*& find, const char* str, msvc8::string& dest); // 0x00938CB0
	void STR_GetTokens( StrArg find, const char* str, msvc8::vector<msvc8::string>& dest); // 0x00938F40
	int STR_GetWordStartIndex(msvc8::string& str, int pos); // 0x009384A0
	int STR_GetNextWordStartIndex(msvc8::string& str, int pos); // 0x00938570
	bool STR_EndsWith(StrArg str, StrArg end); // 0x00938190
	bool STR_StartsWith(StrArg str, StrArg start); // 0x00938210
	bool STR_EndsWithNoCase(StrArg str, StrArg end); // 0x00938250
	bool STR_StartsWithNoCase(StrArg str, StrArg start); // 0x009382B0
	bool STR_IsIdent(StrArg str); // 0x009382F0
	int STR_Replace(msvc8::string& str, StrArg what, StrArg with, unsigned int unk); // 0x00938B40
	int STR_ParseUInt32(StrArg str); // 0x00938150
	int STR_Xtoi(StrArg str); // 0x009380F0
	bool STR_MatchWildcard(StrArg, StrArg); // 0x00938450
	bool STR_WildcardValidPrefix(StrArg, StrArg); // 0x00938470

	msvc8::string STR_GetWhitespaceCharacters(); // 0x00938C80
	msvc8::string STR_Chop(StrArg str, char chr); // 0x00938BF0
	msvc8::string STR_ToLower(StrArg str); // 0x00938A80
	msvc8::string STR_ToUpper(StrArg str); // 0x009389C0
	msvc8::string STR_TrimWhitespace(StrArg str); // 0x009388C0
	msvc8::string STR_Printf(const char* args...); // 0x00938F10
	msvc8::string STR_Va(const char*& fmt, va_list va); // 0x00938E00
}