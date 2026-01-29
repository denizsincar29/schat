package server

import (
	"testing"
)

// TestNormalizeNewlines tests the newline normalization function
func TestNormalizeNewlines(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Single LF",
			input:    "Hello\nWorld",
			expected: "Hello\r\nWorld",
		},
		{
			name:     "Multiple LF",
			input:    "Line1\nLine2\nLine3",
			expected: "Line1\r\nLine2\r\nLine3",
		},
		{
			name:     "Already CRLF",
			input:    "Hello\r\nWorld",
			expected: "Hello\r\nWorld",
		},
		{
			name:     "Mixed LF and CRLF",
			input:    "Line1\nLine2\r\nLine3\n",
			expected: "Line1\r\nLine2\r\nLine3\r\n",
		},
		{
			name:     "No newlines",
			input:    "Hello World",
			expected: "Hello World",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "Only newlines",
			input:    "\n\n\n",
			expected: "\r\n\r\n\r\n",
		},
		{
			name:     "Welcome text example",
			input:    "Welcome to schat!\n\nType /help for available commands.\n",
			expected: "Welcome to schat!\r\n\r\nType /help for available commands.\r\n",
		},
		{
			name:     "Command output with multiple lines",
			input:    "Users in this room:\n  user1\n  user2\n  user3\n",
			expected: "Users in this room:\r\n  user1\r\n  user2\r\n  user3\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeNewlines(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeNewlines() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestNormalizeNewlinesIdempotent verifies that normalizing twice gives the same result
func TestNormalizeNewlinesIdempotent(t *testing.T) {
	inputs := []string{
		"Hello\nWorld",
		"Line1\nLine2\nLine3",
		"Already\r\nNormalized",
		"Mixed\nAnd\r\nNormalized\n",
	}

	for _, input := range inputs {
		first := normalizeNewlines(input)
		second := normalizeNewlines(first)
		if first != second {
			t.Errorf("normalizeNewlines is not idempotent for input %q: first=%q, second=%q", input, first, second)
		}
	}
}
