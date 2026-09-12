package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Southclaws/oauthcli/internal/cligen"
	"github.com/Southclaws/oauthcli/internal/oauth"
	"github.com/Southclaws/oauthcli/internal/render"
)

// wellKnownKinds are the documents discover probes, with the specification
// that defines each location.
var wellKnownKinds = []struct {
	kind string
	spec string
}{
	{oauth.KindOAuth, "RFC 8414"},
	{oauth.KindOpenID, "OpenID Connect Discovery 1.0"},
	{oauth.KindResource, "RFC 9728"},
	{"jwks.json", "convention"},
	{oauth.KindFederation, "OpenID Federation 1.0"},
	{oauth.KindCredential, "OpenID for Verifiable Credential Issuance"},
}

// discover probes every well-known location and summarises what the issuer
// supports.
func discover(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.DiscoverParams) (cligen.DiscoveryReport, error) {
	s, err := newSession(cmd, commandIO)
	if err != nil {
		return cligen.DiscoveryReport{}, err
	}
	issuer, err := s.issuer(p.IssuerUrl)
	if err != nil {
		return cligen.DiscoveryReport{}, err
	}

	report := cligen.DiscoveryReport{Issuer: issuer, Probes: []cligen.WellKnownProbe{}, Capabilities: []cligen.Capability{}, Issues: []cligen.Issue{}}
	var primary *oauth.Metadata
	found := 0

	for _, kind := range wellKnownKinds {
		for _, candidate := range oauth.WellKnownURLs(issuer, kind.kind) {
			probe := cligen.WellKnownProbe{Kind: kind.kind, URL: candidate, Spec: oauth.Ptr(kind.spec)}
			started := time.Now()
			response, err := s.Client.Get(ctx, candidate)
			probe.ElapsedMs = int(time.Since(started).Milliseconds())
			switch {
			case err != nil:
				probe.Status = "error"
				probe.Error = oauth.Ptr(err.Error())
			case response.Status == 200:
				probe.Status = "found"
				probe.HTTPStatus = &response.Status
				probe.ContentType = oauth.Ptr(response.ContentType())
				found++
				document, jsonErr := response.JSON()
				if jsonErr != nil {
					probe.Status = "error"
					probe.Error = oauth.Ptr(jsonErr.Error())
					break
				}
				probe.Summary = oauth.Ptr(summarise(kind.kind, document))
				switch kind.kind {
				case oauth.KindOAuth, oauth.KindOpenID:
					metadata := &oauth.Metadata{Raw: document, URL: candidate, Kind: kind.kind, Issuer: issuer, Response: response}
					if primary == nil {
						primary = metadata
						doc := cligen.Document(document)
						report.Metadata = &doc
					}
					report.Issues = append(report.Issues, prefixIssues(kind.kind, metadata.Validate(s.Settings.AllowHTTP))...)
				case oauth.KindResource:
					doc := cligen.Document(document)
					report.Resource = &doc
					resource := &oauth.ResourceMetadata{Raw: document, URL: candidate, Resource: issuer, Response: response}
					report.Issues = append(report.Issues, prefixIssues(kind.kind, resource.Validate(s.Settings.AllowHTTP))...)
				}
			default:
				probe.Status = "missing"
				probe.HTTPStatus = &response.Status
			}
			report.Probes = append(report.Probes, probe)
			if probe.Status == "found" {
				break
			}
		}
	}

	report.Issues = dedupeIssues(report.Issues)
	if primary != nil {
		report.Capabilities = primary.Capabilities()
		if p.Keys {
			if jwksURI := primary.String("jwks_uri"); jwksURI != "" {
				set, err := s.Client.FetchKeys(ctx, jwksURI)
				if err != nil {
					report.Issues = append(report.Issues, oauth.Errorf("jwks-unreachable", "RFC 8414 §2", "jwks_uri", "%v", err))
				} else {
					report.Keys = oauth.DescribeKeySet(set, false).Keys
				}
			}
		}
	}

	format := string(p.Format)
	if machineReadable(format) {
		return report, nil
	}

	rows := make([][]string, 0, len(report.Probes))
	for _, probe := range report.Probes {
		status := probe.Status
		if probe.HTTPStatus != nil {
			status = fmt.Sprintf("%s (%d)", probe.Status, *probe.HTTPStatus)
		}
		rows = append(rows, []string{probe.Kind, status, probe.URL, fmt.Sprintf("%dms", probe.ElapsedMs)})
	}
	if format == "plain" {
		s.Out.Plain(rows)
		return report, nil
	}
	if format == "table" {
		s.Out.Table([]string{"DOCUMENT", "STATUS", "URL", "TIME"}, rows)
		return report, nil
	}

	out := s.Out
	out.Title(issuer, fmt.Sprintf("%d of %d well-known documents found", found, len(wellKnownKinds)))
	out.Println()
	for _, probe := range report.Probes {
		glyph, style := out.Status(probe.Status)
		line := fmt.Sprintf("%s %-30s %s", style.Render(glyph), probe.Kind, out.T.Styles.URL.Render(probe.URL))
		if probe.HTTPStatus != nil && probe.Status != "found" {
			line += out.T.Styles.Faint.Render(fmt.Sprintf("  %d", *probe.HTTPStatus))
		}
		if probe.Error != nil {
			line += out.T.Styles.Bad.Render("  " + render.Truncate(*probe.Error, 60))
		}
		out.Println(line)
		if probe.Summary != nil {
			out.Println("  " + out.T.Styles.Dim.Render(*probe.Summary))
		}
	}

	if primary == nil {
		out.Println()
		out.Errorf("no authorization server metadata at this host")
		out.Notef("%s", oauth.MultiTenantHint)
		return report, fmt.Errorf("%w: %s publishes no metadata document", ErrNotFound, issuer)
	}

	out.Section("Capabilities")
	renderCapabilities(out, report.Capabilities)

	if len(report.Keys) > 0 {
		out.Section(fmt.Sprintf("Keys (%d)", len(report.Keys)))
		for _, key := range report.Keys {
			out.Println("  " + keyLine(out, key))
		}
	}

	if len(report.Issues) > 0 {
		out.Section("Findings  " + out.T.Styles.Faint.Render(issueSummary(report.Issues)))
		s.printIssues(out, report.Issues)
	}
	out.Println()
	out.Notef("next: oauthcli check %s  (full conformance audit)", issuer)
	return report, nil
}

// dedupeIssues drops findings that both metadata documents raised.
func dedupeIssues(issues []cligen.Issue) []cligen.Issue {
	seen := map[string]bool{}
	out := make([]cligen.Issue, 0, len(issues))
	for _, issue := range issues {
		key := issue.Code + "\x00" + issue.Message
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, issue)
	}
	return out
}

func prefixIssues(kind string, issues []cligen.Issue) []cligen.Issue {
	for i := range issues {
		if issues[i].Field != nil {
			issues[i].Field = oauth.Ptr(kind + "." + *issues[i].Field)
		}
	}
	return issues
}

// summarise gives a one-line description of a found document.
func summarise(kind string, document map[string]any) string {
	m := &oauth.Metadata{Raw: document}
	switch kind {
	case oauth.KindOAuth, oauth.KindOpenID:
		grants := m.GrantTypes()
		return fmt.Sprintf("issuer %s · %d endpoints · grants: %s", m.String("issuer"), len(m.Endpoints()), strings.Join(grants, ", "))
	case oauth.KindResource:
		return fmt.Sprintf("resource %s · authorization servers: %s", m.String("resource"), strings.Join(m.Strings("authorization_servers"), ", "))
	case "jwks.json":
		keys, _ := document["keys"].([]any)
		return fmt.Sprintf("%d key(s)", len(keys))
	default:
		keys := oauth.SortedKeys(document)
		if len(keys) > 6 {
			keys = append(keys[:6], "…")
		}
		return strings.Join(keys, ", ")
	}
}

func renderCapabilities(out *render.Printer, capabilities []cligen.Capability) {
	for _, capability := range capabilities {
		glyph, style := out.Status("skip")
		if capability.Supported {
			glyph, style = out.Status("pass")
		}
		detail := ""
		if capability.Detail != nil && capability.Supported {
			detail = out.T.Styles.Faint.Render("  " + render.Truncate(*capability.Detail, max(20, out.Width-60)))
		}
		out.Printf("  %s %-46s %s%s\n", style.Render(glyph), capability.Title, out.T.Styles.Dim.Render(capability.Spec), detail)
	}
}

func keyLine(out *render.Printer, key cligen.Jwk) string {
	parts := []string{out.T.Styles.Accent.Render(deref(key.Kid, "(no kid)")), key.Kty}
	if key.Alg != nil {
		parts = append(parts, *key.Alg)
	}
	if key.Crv != nil {
		parts = append(parts, *key.Crv)
	}
	if key.Bits != nil {
		parts = append(parts, fmt.Sprintf("%d bits", *key.Bits))
	}
	if key.Use != nil {
		parts = append(parts, "use="+*key.Use)
	}
	line := strings.Join(parts, " · ")
	for _, issue := range key.Issues {
		if issue.Severity == "error" {
			line += "  " + out.T.Styles.Bad.Render(out.T.Symbols.Bad+" "+issue.Message)
		}
	}
	return line
}

func deref(s *string, fallback string) string {
	if s == nil || *s == "" {
		return fallback
	}
	return *s
}

// metadata fetches and validates the authorization server metadata.
func metadata(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.MetadataParams) (cligen.MetadataReport, error) {
	s, err := newSession(cmd, commandIO)
	if err != nil {
		return cligen.MetadataReport{}, err
	}
	issuer, err := s.issuer(p.IssuerUrl)
	if err != nil {
		return cligen.MetadataReport{}, err
	}
	doc, err := s.Client.FetchMetadata(ctx, issuer, string(p.Kind))
	if err != nil {
		return cligen.MetadataReport{}, wrapFetch(err)
	}

	report := cligen.MetadataReport{
		URL:          doc.URL,
		Issuer:       issuer,
		Kind:         doc.Kind,
		Metadata:     cligen.Document(doc.Raw),
		Endpoints:    doc.Endpoints(),
		Capabilities: doc.Capabilities(),
		Issues:       doc.Validate(s.Settings.AllowHTTP),
	}
	if report.Endpoints == nil {
		report.Endpoints = []cligen.Endpoint{}
	}
	if report.Issues == nil {
		report.Issues = []cligen.Issue{}
	}
	report.HTTPStatus = &doc.Response.Status
	report.ElapsedMs = oauth.Ptr(int(doc.Response.Elapsed.Milliseconds()))

	format := string(p.Format)
	if p.Raw {
		if machineReadable(format) {
			// The generated encoder would wrap the document in the report
			// shape; raw means the document alone.
			return report, encodeRaw(s, format, doc.Raw)
		}
		pretty, _ := json.MarshalIndent(doc.Raw, "", "  ")
		fmt.Fprintln(s.Out.Raw(), string(pretty))
		return report, nil
	}
	if machineReadable(format) {
		if oauth.HasErrors(report.Issues) {
			return report, s.fail(format, report, fmt.Errorf("%w: the metadata document has errors", ErrFailed))
		}
		return report, nil
	}
	if format == "markdown" {
		return report, s.Out.Markdown(metadataMarkdown(report))
	}

	out := s.Out
	out.Title(doc.String("issuer"), doc.URL)
	out.KV([]render.Field{
		render.F("Document", doc.Kind),
		render.F("Fetched in", fmt.Sprintf("%dms", *report.ElapsedMs)),
		render.F("Grant types", strings.Join(doc.GrantTypes(), ", ")),
		render.F("Response types", strings.Join(doc.Strings("response_types_supported"), ", ")),
		render.F("Client auth", strings.Join(doc.TokenAuthMethods(), ", ")),
		render.F("PKCE", wrapList(doc.Strings("code_challenge_methods_supported"), 80)),
		render.F("Scopes", wrapList(doc.Strings("scopes_supported"), 80)),
	})

	out.Section("Endpoints")
	keyStyle := out.T.Styles.Key.Width(40)
	for _, endpoint := range report.Endpoints {
		out.Printf("  %s %s\n", keyStyle.Render(endpoint.Name), out.T.Styles.URL.Render(endpoint.URL))
	}

	out.Section("Capabilities")
	renderCapabilities(out, report.Capabilities)

	out.Section("Findings  " + out.T.Styles.Faint.Render(issueSummary(report.Issues)))
	if len(report.Issues) == 0 {
		out.Okf("the document is valid")
	}
	s.printIssues(out, report.Issues)

	if oauth.HasErrors(report.Issues) {
		return report, fmt.Errorf("%w: the metadata document has errors", ErrFailed)
	}
	return report, nil
}

func encodeRaw(s *session, format string, document map[string]any) error {
	if format == "json" {
		encoder := json.NewEncoder(s.Out.Raw())
		encoder.SetIndent("", "  ")
		return encoder.Encode(document)
	}
	return nil
}

func wrapList(items []string, width int) string {
	if len(items) == 0 {
		return "(not advertised)"
	}
	var lines []string
	var current string
	for _, item := range items {
		if current != "" && len(current)+len(item)+1 > width {
			lines = append(lines, current)
			current = ""
		}
		if current != "" {
			current += " "
		}
		current += item
	}
	lines = append(lines, current)
	return strings.Join(lines, "\n")
}

func metadataMarkdown(report cligen.MetadataReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", report.Issuer)
	fmt.Fprintf(&b, "Source: `%s` (%s)\n\n", report.URL, report.Kind)
	b.WriteString("## Endpoints\n\n| Endpoint | URL |\n|---|---|\n")
	for _, endpoint := range report.Endpoints {
		fmt.Fprintf(&b, "| `%s` | %s |\n", endpoint.Name, endpoint.URL)
	}
	b.WriteString("\n## Capabilities\n\n| Capability | Specification | Supported |\n|---|---|---|\n")
	for _, capability := range report.Capabilities {
		mark := "no"
		if capability.Supported {
			mark = "yes"
		}
		fmt.Fprintf(&b, "| %s | %s | %s |\n", capability.Title, capability.Spec, mark)
	}
	b.WriteString("\n## Findings\n\n")
	if len(report.Issues) == 0 {
		b.WriteString("No problems found.\n")
	}
	for _, issue := range report.Issues {
		fmt.Fprintf(&b, "- **%s** %s", issue.Severity, issue.Message)
		if issue.Spec != nil {
			fmt.Fprintf(&b, " _(%s)_", *issue.Spec)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// jwks fetches and inspects a key set.
func jwks(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.JwksParams) (cligen.KeySet, error) {
	s, err := newSession(cmd, commandIO)
	if err != nil {
		return cligen.KeySet{}, err
	}

	source := p.Source
	looksLikeIssuer := source == "" || (strings.Contains(source, "://") && !strings.Contains(source, "jwks") && !strings.HasSuffix(source, ".json"))
	if looksLikeIssuer {
		issuer, err := s.issuer(source)
		if err != nil {
			return cligen.KeySet{}, err
		}
		metadata, err := s.metadataFor(ctx, issuer)
		if err != nil {
			return cligen.KeySet{}, err
		}
		source = metadata.String("jwks_uri")
		if source == "" {
			return cligen.KeySet{}, fmt.Errorf("%w: %s advertises no jwks_uri", ErrNotFound, issuer)
		}
	}
	set, err := s.Client.FetchKeys(ctx, source)
	if err != nil {
		return cligen.KeySet{}, err
	}
	report := oauth.DescribeKeySet(set, p.Pem)
	if p.Kid != "" {
		filtered := report.Keys[:0]
		for _, key := range report.Keys {
			if key.Kid != nil && *key.Kid == p.Kid {
				filtered = append(filtered, key)
			}
		}
		if len(filtered) == 0 {
			return report, fmt.Errorf("%w: no key with kid %q in %s", ErrNotFound, p.Kid, source)
		}
		report.Keys = filtered
	}

	format := string(p.Format)
	if machineReadable(format) {
		if oauth.HasErrors(report.Issues) || anyKeyErrors(report.Keys) {
			return report, s.fail(format, report, fmt.Errorf("%w: the key set has errors", ErrFailed))
		}
		return report, nil
	}
	rows := make([][]string, 0, len(report.Keys))
	for _, key := range report.Keys {
		rows = append(rows, []string{deref(key.Kid, "-"), key.Kty, deref(key.Alg, "-"), deref(key.Use, "-"), fmt.Sprint(derefInt(key.Bits)), key.Thumbprint})
	}
	switch format {
	case "plain":
		s.Out.Plain(rows)
		return report, nil
	case "table":
		s.Out.Table([]string{"KID", "KTY", "ALG", "USE", "BITS", "THUMBPRINT"}, rows)
		return report, nil
	}

	out := s.Out
	out.Title(source, fmt.Sprintf("%d key(s)", len(report.Keys)))
	for _, key := range report.Keys {
		out.Println()
		out.Println(keyLine(out, key))
		fields := []render.Field{render.F("Thumbprint", key.Thumbprint)}
		if key.Certificate != nil {
			fields = append(fields,
				render.F("Certificate", key.Certificate.Subject),
				render.F("Issued by", key.Certificate.Issuer),
				render.F("Valid until", key.Certificate.NotAfter.Format(time.RFC3339)),
			)
		}
		out.KV(fields)
		s.printIssues(out, key.Issues)
		if key.Pem != nil {
			out.Print(out.T.Styles.Dim.Render(*key.Pem))
		}
	}
	if len(report.Issues) > 0 {
		out.Println()
		s.printIssues(out, report.Issues)
	}
	if oauth.HasErrors(report.Issues) || anyKeyErrors(report.Keys) {
		return report, fmt.Errorf("%w: the key set has errors", ErrFailed)
	}
	return report, nil
}

func anyKeyErrors(keys []cligen.Jwk) bool {
	for _, key := range keys {
		if oauth.HasErrors(key.Issues) {
			return true
		}
	}
	return false
}

func derefInt(v *int) int {
	if v == nil {
		return 0
	}
	return *v
}

// resource fetches and validates RFC 9728 protected resource metadata.
func resource(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.ResourceParams) (cligen.ResourceReport, error) {
	s, err := newSession(cmd, commandIO)
	if err != nil {
		return cligen.ResourceReport{}, err
	}
	target, err := oauth.NormalizeIssuer(p.ResourceUrl)
	if err != nil {
		return cligen.ResourceReport{}, err
	}
	report := cligen.ResourceReport{URL: target, AuthorizationServers: []string{}, Issues: []cligen.Issue{}}

	if p.Probe {
		challenge, response, err := s.Client.ProbeResource(ctx, p.ResourceUrl)
		if err != nil {
			return report, err
		}
		if challenge != nil {
			report.Challenge = &cligen.Challenge{Scheme: challenge.Scheme, Params: challenge.Params, HTTPStatus: &response.Status}
			if response.Status != 401 {
				report.Issues = append(report.Issues, oauth.Warnf("probe-status", "RFC 6750 §3", "", "an unauthenticated request answered HTTP %d, want 401", response.Status))
			}
			if challenge.Params["resource_metadata"] == "" {
				report.Issues = append(report.Issues, oauth.Infof("no-resource-metadata-param", "RFC 9728 §5.1", "", "the challenge does not point at the metadata with resource_metadata"))
			}
		} else {
			report.Issues = append(report.Issues, oauth.Errorf("no-challenge", "RFC 6750 §3", "", "an unauthenticated request answered HTTP %d with no WWW-Authenticate header", response.Status))
		}
	}

	metadata, err := s.Client.FetchResourceMetadata(ctx, target)
	if err != nil {
		report.MetadataURL = strings.Join(oauth.WellKnownURLs(target, oauth.KindResource), " or ")
		report.Metadata = map[string]any{}
		if machineReadable(string(p.Format)) {
			return report, wrapFetch(err)
		}
		renderResource(s, report)
		return report, wrapFetch(err)
	}
	report.MetadataURL = metadata.URL
	report.Metadata = cligen.Document(metadata.Raw)
	report.Resource = oauth.Ptr(metadata.String("resource"))
	report.AuthorizationServers = metadata.Strings("authorization_servers")
	report.Issues = append(report.Issues, metadata.Validate(s.Settings.AllowHTTP)...)

	if p.Follow {
		for _, server := range report.AuthorizationServers {
			if _, err := s.Client.FetchMetadata(ctx, server, "auto"); err != nil {
				report.Issues = append(report.Issues, oauth.Errorf("authorization-server-unreachable", "RFC 9728 §2", "authorization_servers", "%s publishes no metadata: %v", server, err))
			} else {
				report.Issues = append(report.Issues, oauth.Infof("authorization-server-ok", "RFC 9728 §2", "authorization_servers", "%s publishes metadata", server))
			}
		}
	}

	if machineReadable(string(p.Format)) {
		if oauth.HasErrors(report.Issues) {
			return report, s.fail(string(p.Format), report, fmt.Errorf("%w: the resource metadata has errors", ErrFailed))
		}
		return report, nil
	}
	renderResource(s, report)
	if oauth.HasErrors(report.Issues) {
		return report, fmt.Errorf("%w: the resource metadata has errors", ErrFailed)
	}
	return report, nil
}

func renderResource(s *session, report cligen.ResourceReport) {
	out := s.Out
	out.Title(report.URL, report.MetadataURL)
	if report.Challenge != nil {
		out.Section("WWW-Authenticate challenge")
		fields := []render.Field{render.F("Scheme", report.Challenge.Scheme)}
		names := make([]string, 0, len(report.Challenge.Params))
		for name := range report.Challenge.Params {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fields = append(fields, render.F(name, report.Challenge.Params[name]))
		}
		out.KV(fields)
	}
	if document, ok := report.Metadata.(map[string]any); ok && len(document) > 0 {
		out.Section("Metadata")
		fields := []render.Field{}
		for _, key := range oauth.SortedKeys(document) {
			fields = append(fields, render.F(key, fmt.Sprint(document[key])))
		}
		out.KV(fields)
	}
	out.Section("Findings  " + out.T.Styles.Faint.Render(issueSummary(report.Issues)))
	if len(report.Issues) == 0 {
		out.Okf("the document is valid")
	}
	s.printIssues(out, report.Issues)
}
