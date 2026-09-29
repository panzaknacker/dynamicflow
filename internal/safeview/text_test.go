package safeview

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestTextPreservesSafeUnicodeAndLimitsVisibleRunes(t *testing.T) {
	tests := []struct {
		name  string
		input string
		limit int
		want  string
	}{
		{name: "empty", input: "", limit: 8, want: ""},
		{name: "non-positive", input: "safe", limit: 0, want: ""},
		{name: "unchanged", input: "München ✓", limit: 20, want: "München ✓"},
		{name: "exact", input: "abc", limit: 3, want: "abc"},
		{name: "truncate", input: "abcdef", limit: 4, want: "abc…"},
		{name: "single-rune-limit", input: "日本", limit: 1, want: "…"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Text(test.input, test.limit); got != test.want {
				t.Fatalf("Text(%q, %d) = %q, want %q", test.input, test.limit, got, test.want)
			}
			if got := utf8.RuneCountInString(Text(test.input, test.limit)); got > test.limit && test.limit > 0 {
				t.Fatalf("result has %d runes, limit is %d", got, test.limit)
			}
		})
	}
}

func TestTextReplacesControlsInvalidUTF8AndBidiFormatting(t *testing.T) {
	input := "a\x00\n\x7f\u0085\u202eb\u2067c\u2069" + string([]byte{0xff}) + "z"
	want := "a�����b�c��z"
	if got := Text(input, 64); got != want {
		t.Fatalf("Text() = %q, want %q", got, want)
	}
}

func TestTextConsumesTerminalSequencesAsSingleUnits(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "CSI", input: "a\x1b[31mred\x1b[0mz", want: "a�red�z"},
		{name: "OSC BEL", input: "a\x1b]52;c;payload\az", want: "a�z"},
		{name: "OSC ST", input: "a\x1b]8;;https://invalid.example\x1b\\link\x1b]8;;\x1b\\z", want: "a�link�z"},
		{name: "C1 OSC", input: "a\u009d52;c;payload\u009cz", want: "a�z"},
		{name: "raw C1 OSC", input: "a\x9dpayload\x9cz", want: "a�z"},
		{name: "DCS", input: "a\x1bPprivate\x1b\\z", want: "a�z"},
		{name: "simple escape", input: "a\x1bcz", want: "a�z"},
		{name: "unterminated OSC", input: "a\x1b]52;c;payload", want: "a�"},
		{name: "lone escape", input: "a\x1b", want: "a�"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Text(test.input, 128); got != test.want {
				t.Fatalf("Text(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}

func TestTextReplacesEveryC0AndC1Control(t *testing.T) {
	var input strings.Builder
	for r := rune(0); r <= 0x1f; r++ {
		input.WriteRune(r)
	}
	for r := rune(0x7f); r <= 0x9f; r++ {
		input.WriteRune(r)
	}
	got := Text(input.String(), 256)
	for _, r := range got {
		if unicode.IsControl(r) {
			t.Fatalf("result contains control rune U+%04X", r)
		}
	}
	if !utf8.ValidString(got) {
		t.Fatal("result is not valid UTF-8")
	}
}

func TestTextReplacesEveryBidirectionalFormattingControl(t *testing.T) {
	controls := []rune{
		'\u061c', '\u200e', '\u200f',
		'\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
		'\u2066', '\u2067', '\u2068', '\u2069',
		'\u206a', '\u206b', '\u206c', '\u206d', '\u206e', '\u206f',
	}
	input := "left" + string(controls) + "right"
	got := Text(input, 128)
	if strings.ContainsAny(got, string(controls)) {
		t.Fatalf("result retained a bidirectional formatting control: %q", got)
	}
	if count := strings.Count(got, string(replacement)); count != len(controls) {
		t.Fatalf("result contains %d replacements, want %d: %q", count, len(controls), got)
	}
}

func TestTextTruncationCountsReplacementAndEllipsis(t *testing.T) {
	if got := Text("a\x1b[31mbc", 3); got != "a�…" {
		t.Fatalf("Text() = %q, want %q", got, "a�…")
	}
}

func FuzzTextNeverEmitsUnsafeRunes(f *testing.F) {
	for _, seed := range []string{
		"ordinary",
		"\x1b]52;c;payload\a",
		"\u202eevil",
		string([]byte{0xff, 0xfe, 0xfd}),
	} {
		f.Add(seed, uint8(32))
	}
	f.Fuzz(func(t *testing.T, input string, rawLimit uint8) {
		limit := int(rawLimit)
		got := Text(input, limit)
		if !utf8.ValidString(got) {
			t.Fatal("result is not valid UTF-8")
		}
		if utf8.RuneCountInString(got) > limit {
			t.Fatalf("result exceeds rune limit %d", limit)
		}
		for _, r := range got {
			if unicode.IsControl(r) || isBidirectionalControl(r) {
				t.Fatalf("unsafe rune U+%04X in result", r)
			}
		}
	})
}
