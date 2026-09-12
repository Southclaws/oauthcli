package rfcs

import (
	"strings"
	"testing"
)

func TestEveryListedSpecificationIsEmbedded(t *testing.T) {
	for _, spec := range Specs {
		text, err := Text(&spec)
		if err != nil {
			t.Errorf("%s: %v", spec.ID, err)
			continue
		}
		if len(text) < 5000 {
			t.Errorf("%s: only %d bytes", spec.ID, len(text))
		}
	}
}

func TestFindAcceptsIdsAliasesAndNumbers(t *testing.T) {
	for query, want := range map[string]string{
		"rfc6749": "rfc6749", "6749": "rfc6749", "RFC 7636": "rfc7636", "pkce": "rfc7636",
		"oauth2.1": "oauth2.1", "oidc-core": "oidc-core", "discovery": "oidc-discovery", "cimd": "cimd", "dpop": "rfc9449",
	} {
		spec, err := Find(query)
		if err != nil {
			t.Errorf("%q: %v", query, err)
			continue
		}
		if spec.ID != want {
			t.Errorf("%q resolved to %s, want %s", query, spec.ID, want)
		}
	}
	if _, err := Find("rfc1"); err == nil {
		t.Error("unknown specification must fail")
	}
}

func TestSectionExtractsOneSectionWithoutPageFurniture(t *testing.T) {
	spec, _ := Find("rfc6749")
	text, _ := Text(spec)
	section, err := Section(text, "5.2")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(section, "5.2.  Error Response") {
		t.Fatalf("section starts with %q", strings.SplitN(section, "\n", 2)[0])
	}
	for _, want := range []string{"invalid_request", "unsupported_grant_type", "Cache-Control: no-store"} {
		if !strings.Contains(section, want) {
			t.Errorf("section 5.2 lacks %q", want)
		}
	}
	if strings.Contains(section, "[Page ") || strings.Contains(section, "Hardt") {
		t.Error("page furniture was not removed")
	}
	if strings.Contains(section, "6.  Refreshing an Access Token") {
		t.Error("the next section leaked into the output")
	}

	nested, err := Section(text, "4.1.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(nested, "unsupported_response_type") {
		t.Error("nested section 4.1.2.1 is incomplete")
	}
	if _, err := Section(text, "99.9"); err == nil {
		t.Error("unknown section must fail")
	}
}

func TestSectionWorksForOpenIDAndDrafts(t *testing.T) {
	spec, _ := Find("oidc-core")
	text, _ := Text(spec)
	section, err := Section(text, "3.1.3.7")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(section, "ID Token Validation") || !strings.Contains(section, "nonce") {
		t.Error("Core §3.1.3.7 is incomplete")
	}
	draft, _ := Find("oauth2.1")
	text, _ = Text(draft)
	if _, err := Section(text, "4.1.2.1"); err != nil {
		t.Fatal(err)
	}
}
