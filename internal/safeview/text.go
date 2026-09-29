// package safeview prepares untrusted text for display in a terminal UI.
package safeview

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	replacement = '\uFFFD'
	ellipsis    = '\u2026'
)

// Text returns a valid UTF-8, terminal-safe representation of value containing
// at most maxRunes visible runes.

// terminal control sequences are replaced as one unit. other control bytes,
// invalid UTF-8 and unicode bidirectional formatting controls are replaced
// individually. when truncation is required, the final rune is an ellipsis and
// counts toward maxRunes. a non-positive limit returns an empty string.
func Text(value string, maxRunes int) string {
	if maxRunes <= 0 || value == "" {
		return ""
	}

	capacity := maxRunes
	if capacity > len(value) {
		capacity = len(value)
	}
	output := make([]rune, 0, capacity)
	emitted := 0
	emit := func(r rune) {
		emitted++
		if len(output) < maxRunes {
			output = append(output, r)
		}
	}

	for offset := 0; offset < len(value); {
		switch value[offset] {
		case '\x1b':
			emit(replacement)
			offset = consumeEscape(value, offset)
			continue
		case '\x90', '\x98', '\x9d', '\x9e', '\x9f':
			emit(replacement)
			offset = consumeStringControl(value, offset+1)
			continue
		case '\x9b':
			emit(replacement)
			offset = consumeCSI(value, offset+1)
			continue
		}

		r, size := utf8.DecodeRuneInString(value[offset:])
		if r == utf8.RuneError && size == 1 {
			emit(replacement)
			offset++
			continue
		}
		switch r {
		case '\u0090', '\u0098', '\u009d', '\u009e', '\u009f':
			emit(replacement)
			offset = consumeStringControl(value, offset+size)
		case '\u009b':
			emit(replacement)
			offset = consumeCSI(value, offset+size)
		default:
			if unicode.IsControl(r) || isBidirectionalControl(r) {
				emit(replacement)
			} else {
				emit(r)
			}
			offset += size
		}
	}

	if emitted > maxRunes {
		output[len(output)-1] = ellipsis
	}
	return string(output)
}

func consumeEscape(value string, offset int) int {
	next := offset + 1
	if next >= len(value) {
		return next
	}
	switch value[next] {
	case ']':
		return consumeStringControl(value, next+1)
	case 'P', 'X', '^', '_':
		return consumeStringControl(value, next+1)
	case '[':
		return consumeCSI(value, next+1)
	}

	// ECMA-48 escape functions consist of zero or more intermediate bytes
	// followed by one final byte. if the sequence is incomplete, consume only
	// the introducer and leave ordinary UTF-8 text to the main sanitizer.
	cursor := next
	for cursor < len(value) && value[cursor] >= 0x20 && value[cursor] <= 0x2f {
		cursor++
	}
	if cursor < len(value) && value[cursor] >= 0x30 && value[cursor] <= 0x7e {
		return cursor + 1
	}
	return next
}

func consumeCSI(value string, offset int) int {
	for cursor := offset; cursor < len(value); cursor++ {
		if value[cursor] >= 0x40 && value[cursor] <= 0x7e {
			return cursor + 1
		}
	}
	return len(value)
}

func consumeStringControl(value string, offset int) int {
	for cursor := offset; cursor < len(value); {
		switch value[cursor] {
		case '\a':
			return cursor + 1
		case '\x1b':
			if cursor+1 < len(value) && value[cursor+1] == '\\' {
				return cursor + 2
			}
		case '\x9c':
			return cursor + 1
		}
		if strings.HasPrefix(value[cursor:], "\u009c") {
			return cursor + len("\u009c")
		}
		cursor++
	}
	return len(value)
}

func isBidirectionalControl(r rune) bool {
	switch r {
	case '\u061c', // arabic letter mark
		'\u200e', // left-to-right mark
		'\u200f', // right-to-left mark
		'\u202a', // left-to-right embedding
		'\u202b', // right-to-left embedding
		'\u202c', // pop directional formatting
		'\u202d', // left-to-right override
		'\u202e', // right-to-left override
		'\u2066', // left-to-right isolate
		'\u2067', // right-to-left isolate
		'\u2068', // first strong isolate
		'\u2069': // pop directional isolate
		return true
	default:
		return r >= '\u206a' && r <= '\u206f'
	}
}
