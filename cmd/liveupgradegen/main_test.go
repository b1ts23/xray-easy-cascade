// SPDX-License-Identifier: GPL-3.0-only

package main

import "testing"

func TestReferenceOptions(t *testing.T) {
	options, err := referenceOptions("https://203.0.113.10:28443/example")
	if err != nil {
		t.Fatal(err)
	}
	if options.BasePath != "/example/panel/" || options.Port != 28443 || !options.RequireOperatorCommit {
		t.Fatalf("unexpected reference options: %#v", options)
	}
	for _, unsafe := range []string{
		"", "http://203.0.113.10:28443/example", "https://example.com:28443/example",
		"https://user@203.0.113.10:28443/example", "https://203.0.113.10/example",
	} {
		if _, err := referenceOptions(unsafe); err == nil {
			t.Fatalf("accepted unsafe URL %q", unsafe)
		}
	}
}
