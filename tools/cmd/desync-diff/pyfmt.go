package main

// Text helpers that print values the way Python prints them: the report started as the Python
// desync_diff.py, and these keep its text (str, repr, json.dumps, splitlines) unchanged.

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// decodeText is bytes.decode("utf-8", errors="replace"): each invalid byte becomes U+FFFD.
func decodeText(data []byte) string {
	if utf8.Valid(data) {
		return string(data)
	}
	var b strings.Builder
	for len(data) > 0 {
		r, size := utf8.DecodeRune(data)
		if r == utf8.RuneError && size == 1 {
			b.WriteRune(utf8.RuneError)
		} else {
			b.Write(data[:size])
		}
		data = data[size:]
	}
	return b.String()
}

// splitLines is str.splitlines(): every line boundary Python knows, no trailing empty line.
func splitLines(text string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		switch r {
		case '\r':
			lines = append(lines, text[start:i])
			if i+1 < len(text) && text[i+1] == '\n' {
				size = 2
			}
			start = i + size
		case '\n', '\v', '\f', '\x1c', '\x1d', '\x1e', '\u0085', ' ', ' ':
			lines = append(lines, text[start:i])
			start = i + size
		}
		i += size
	}
	if start < len(text) {
		lines = append(lines, text[start:])
	}
	return lines
}

// pyStrip is str.strip() with no argument.
func pyStrip(s string) string {
	return strings.TrimFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
	})
}

// pyStr is str(value) for a value decoded from JSON (numbers kept as json.Number).
func pyStr(value any) string {
	switch v := value.(type) {
	case nil:
		return "None"
	case bool:
		if v {
			return "True"
		}
		return "False"
	case string:
		return v
	case json.Number:
		return v.String()
	case []any, map[string]any:
		return pyJSON(v) // not printed by any report line today
	}
	return fmt.Sprint(value)
}

// pyJSON is json.dumps(value) with Python's defaults (ASCII only, ", " and ": ").
func pyJSON(value any) string {
	switch v := value.(type) {
	case nil:
		return "null"
	case bool:
		if v {
			return "true"
		}
		return "false"
	case json.Number:
		return v.String()
	case string:
		return pyJSONString(v)
	case []any:
		parts := make([]string, len(v))
		for i, item := range v {
			parts[i] = pyJSON(item)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]any:
		// Python keeps the file's key order; Go's map has none. No report line prints an object.
		keys := sortedKeys(v)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = pyJSONString(k) + ": " + pyJSON(v[k])
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return pyJSONString(fmt.Sprint(value))
}

func pyJSONString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			switch {
			case r < 0x20 || (r > 0x7f && r < 0x10000):
				fmt.Fprintf(&b, `\u%04x`, r)
			case r >= 0x10000:
				r -= 0x10000
				fmt.Fprintf(&b, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
			default:
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// pyRepr is repr(s) for a str.
func pyRepr(s string) string {
	quote := byte('\'')
	if strings.ContainsRune(s, '\'') && !strings.ContainsRune(s, '"') {
		quote = '"'
	}
	var b strings.Builder
	b.WriteByte(quote)
	for _, r := range s {
		switch {
		case r == rune(quote) || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < 0x7f || unicode.IsPrint(r):
			b.WriteRune(r)
		case r < 0x100:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < 0x10000:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
	}
	b.WriteByte(quote)
	return b.String()
}

// pyReprList is repr(list_of_str).
func pyReprList(items []string) string {
	parts := make([]string, len(items))
	for i, s := range items {
		parts[i] = pyRepr(s)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// pyReprTupleList is repr(list_of_tuples_of_str).
func pyReprTupleList(items [][]string) string {
	parts := make([]string, len(items))
	for i, tuple := range items {
		inner := make([]string, len(tuple))
		for j, s := range tuple {
			inner[j] = pyRepr(s)
		}
		if len(inner) == 1 {
			parts[i] = "(" + inner[0] + ",)"
		} else {
			parts[i] = "(" + strings.Join(inner, ", ") + ")"
		}
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// pyEqual is == for two values decoded from JSON: 1 == 1.0 and True == 1, as in Python.
func pyEqual(a, b any) bool {
	fa, aNum := pyNumber(a)
	fb, bNum := pyNumber(b)
	if aNum && bNum {
		return fa == fb
	}
	if aNum != bNum {
		return false
	}
	switch av := a.(type) {
	case nil:
		return b == nil
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	}
	return pyJSON(a) == pyJSON(b)
}

func pyNumber(value any) (float64, bool) {
	switch v := value.(type) {
	case bool:
		if v {
			return 1, true
		}
		return 0, true
	case json.Number:
		f, err := strconv.ParseFloat(v.String(), 64)
		return f, err == nil
	}
	return 0, false
}

// pyTruthy is bool(value).
func pyTruthy(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case bool:
		return v
	case string:
		return v != ""
	case json.Number:
		f, _ := pyNumber(v)
		return f != 0
	case []any:
		return len(v) > 0
	case map[string]any:
		return len(v) > 0
	}
	return true
}

// pyInt is int(value) for a JSON value that should be an integer.
func pyInt(value any) (int, bool) {
	switch v := value.(type) {
	case bool:
		if v {
			return 1, true
		}
		return 0, true
	case json.Number:
		n, err := strconv.Atoi(v.String())
		return n, err == nil
	}
	return 0, false
}

// pyQuote is urllib.parse.quote(s) (safe "/").
func pyQuote(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
			c == '_' || c == '.' || c == '-' || c == '~' || c == '/' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}
