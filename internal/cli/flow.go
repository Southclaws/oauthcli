package cli

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"
	"github.com/spf13/cobra"

	"github.com/Southclaws/oauthcli/internal/cligen"
	"github.com/Southclaws/oauthcli/internal/oauth"
	"github.com/Southclaws/oauthcli/internal/render"
)

// flowCode runs the authorization code flow with PKCE.
func flowCode(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.FlowCodeParams) (cligen.TokenResponse, error) {
	s, err := newSession(cmd, commandIO)
	if err != nil {
		return cligen.TokenResponse{}, err
	}
	issuer, err := s.issuer("")
	if err != nil {
		return cligen.TokenResponse{}, err
	}
	metadata, err := s.metadataFor(ctx, issuer)
	if err != nil {
		return cligen.TokenResponse{}, err
	}
	if metadata.String("authorization_endpoint") == "" {
		return cligen.TokenResponse{}, fmt.Errorf("%w: %s advertises no authorization_endpoint", ErrNotFound, issuer)
	}
	credentials, err := s.credentials()
	if err != nil {
		return cligen.TokenResponse{}, err
	}
	if credentials.ClientID == "" {
		return cligen.TokenResponse{}, errors.New("no client id: pass --client-id or configure a profile")
	}
	extra, err := parseParams(p.Param)
	if err != nil {
		return cligen.TokenResponse{}, err
	}
	dpop, err := s.dpop()
	if err != nil {
		return cligen.TokenResponse{}, err
	}

	var listener *oauth.Listener
	redirectURI := s.Settings.RedirectURI
	if !p.Manual {
		listener, err = oauth.Listen(redirectURI, p.Port)
		if err != nil {
			return cligen.TokenResponse{}, err
		}
		defer listener.Close()
		redirectURI = listener.RedirectURI
	} else if redirectURI == "" {
		return cligen.TokenResponse{}, errors.New("--manual needs --redirect-uri, the URI registered for the client")
	}

	state := p.State
	if state == "" {
		state = oauth.NewState()
	}
	scopes := s.Settings.Scopes
	nonce := p.Nonce
	if nonce == "" && containsString(scopes, "openid") {
		nonce = oauth.NewNonce()
	}
	request := &oauth.AuthorizationRequest{
		Endpoint:     metadata.String("authorization_endpoint"),
		ClientID:     credentials.ClientID,
		RedirectURI:  redirectURI,
		Scopes:       scopes,
		State:        state,
		Nonce:        nonce,
		Audience:     s.Settings.Audience,
		Resources:    s.Settings.Resources,
		Prompt:       p.Prompt,
		LoginHint:    p.LoginHint,
		MaxAge:       p.MaxAge,
		ResponseMode: string(p.ResponseMode),
		Extra:        url.Values(extra),
	}
	var verifier *oauth.PKCE
	if !p.NoPkce {
		verifier, err = oauth.NewPKCE(64)
		if err != nil {
			return cligen.TokenResponse{}, err
		}
		request.PKCE = verifier
	} else {
		s.Err.Warnf("PKCE is disabled; OAuth 2.1 requires it")
	}

	var authorizeURL string
	var issues []cligen.Issue
	if p.Par {
		requestURI, expiresIn, parIssues, err := s.Client.Push(ctx, metadata.String("pushed_authorization_request_endpoint"), request, credentials, metadata.TokenAuthMethods(), dpop)
		if err != nil {
			return cligen.TokenResponse{}, oauthError(err)
		}
		issues = append(issues, parIssues...)
		s.Err.Notef("pushed the authorization request; request_uri valid for %ds", expiresIn)
		u, _ := url.Parse(request.Endpoint)
		query := u.Query()
		query.Set("client_id", credentials.ClientID)
		query.Set("request_uri", requestURI)
		u.RawQuery = query.Encode()
		authorizeURL = u.String()
	} else {
		authorizeURL, err = request.URL()
		if err != nil {
			return cligen.TokenResponse{}, err
		}
	}

	errOut := s.Err
	errOut.Title("Authorization code flow", fmt.Sprintf("client %s · redirect %s", credentials.ClientID, redirectURI))
	errOut.Println(errOut.T.Styles.Dim.Render("Open this URL to sign in:"))
	errOut.Println(errOut.T.Styles.URL.Render(authorizeURL))
	errOut.Println()
	if !p.NoBrowser {
		if err := oauth.OpenBrowser(authorizeURL); err != nil {
			errOut.Warnf("could not open a browser: %v", err)
		} else {
			errOut.Notef("opened the browser")
		}
	}

	var callback *oauth.Callback
	if p.Manual {
		errOut.Notef("after signing in, paste the full redirect URL (or just the code) here:")
		line, err := promptLine("Redirect URL or code", s.in)
		if err != nil {
			return cligen.TokenResponse{}, err
		}
		callback, err = oauth.ParseCallback(line)
		if err != nil {
			return cligen.TokenResponse{}, err
		}
	} else {
		errOut.Notef("waiting up to %s for the browser to return to %s", render.Duration(p.Wait), redirectURI)
		waitCtx, cancel := context.WithTimeout(ctx, p.Wait)
		defer cancel()
		callback, err = listener.Wait(waitCtx)
		if err != nil {
			return cligen.TokenResponse{}, err
		}
	}

	issParameter, _ := metadata.Bool("authorization_response_iss_parameter_supported")
	callbackIssues, err := oauth.ValidateCallback(callback, state, issuer, issParameter)
	issues = append(issues, callbackIssues...)
	if err != nil {
		return cligen.TokenResponse{}, oauthError(err)
	}
	errOut.Okf("received an authorization code")

	params := url.Values{"code": {callback.Code}, "redirect_uri": {redirectURI}}
	if verifier != nil {
		params.Set("code_verifier", verifier.Verifier)
	}
	result, err := s.Client.Token(ctx, oauth.TokenRequest{
		Endpoint:    metadata.String("token_endpoint"),
		Grant:       oauth.GrantAuthorizationCode,
		Credentials: credentials,
		Advertised:  metadata.TokenAuthMethods(),
		Params:      params,
		DPoP:        dpop,
	})
	if err != nil {
		return cligen.TokenResponse{}, oauthError(err)
	}
	result.Issues = append(result.Issues, issues...)
	if containsString(scopes, "openid") && result.IDToken == "" {
		result.Issues = append(result.Issues, oauth.Errorf("id-token-missing", "OpenID Connect Core 1.0 §3.1.3.3", "id_token", "openid was requested but no id_token was returned"))
	}
	return s.finishToken(ctx, result, issuer, metadata, dpop, p.Save, p.NoVerify, string(p.Format), nonce)
}

// flowDevice runs the device authorization flow.
func flowDevice(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.FlowDeviceParams) (cligen.TokenResponse, error) {
	s, err := newSession(cmd, commandIO)
	if err != nil {
		return cligen.TokenResponse{}, err
	}
	issuer, err := s.issuer("")
	if err != nil {
		return cligen.TokenResponse{}, err
	}
	metadata, err := s.metadataFor(ctx, issuer)
	if err != nil {
		return cligen.TokenResponse{}, err
	}
	credentials, err := s.credentials()
	if err != nil {
		return cligen.TokenResponse{}, err
	}
	if credentials.ClientID == "" {
		return cligen.TokenResponse{}, errors.New("no client id: pass --client-id or configure a profile")
	}
	extra, err := parseParams(p.Param)
	if err != nil {
		return cligen.TokenResponse{}, err
	}
	dpop, err := s.dpop()
	if err != nil {
		return cligen.TokenResponse{}, err
	}

	auth, err := s.Client.DeviceAuthorize(ctx, metadata.String("device_authorization_endpoint"), credentials, metadata.TokenAuthMethods(), s.Settings.Scopes, s.Settings.Audience, s.Settings.Resources, url.Values(extra))
	if err != nil {
		if strings.Contains(err.Error(), "no device_authorization_endpoint") {
			return cligen.TokenResponse{}, fmt.Errorf("%w: %w", ErrNotFound, err)
		}
		return cligen.TokenResponse{}, oauthError(err)
	}

	errOut := s.Err
	errOut.Title("Device authorization flow", fmt.Sprintf("code expires in %s", render.Duration(time.Duration(auth.ExpiresIn)*time.Second)))
	target := auth.VerificationURIComplete
	if target == "" {
		target = auth.VerificationURI
	}
	var box strings.Builder
	box.WriteString(errOut.T.Styles.Dim.Render("Visit  ") + errOut.T.Styles.URL.Render(auth.VerificationURI) + "\n")
	box.WriteString(errOut.T.Styles.Dim.Render("Enter  ") + errOut.T.Styles.Title.Render(spaceCode(auth.UserCode)))
	errOut.Box(box.String())
	if p.Qr {
		if err := renderQR(errOut, target); err != nil {
			errOut.Warnf("cannot draw a QR code: %v", err)
		}
	}
	if !p.NoBrowser && target != "" {
		if err := oauth.OpenBrowser(target); err == nil {
			errOut.Notef("opened the browser")
		}
	}
	s.printIssues(errOut, auth.Issues)

	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	frame := 0
	result, err := s.Client.DevicePoll(ctx, metadata.String("token_endpoint"), auth, credentials, metadata.TokenAuthMethods(), dpop, func(status oauth.DevicePollStatus) {
		frame++
		message := fmt.Sprintf("%s waiting for approval (%s, poll %d)", frames[frame%len(frames)], status.Waiting, status.Attempt)
		if errOut.TTY {
			errOut.Printf("\r%s", errOut.T.Styles.Dim.Render(message))
		} else if status.Attempt == 1 || status.SlowDown {
			errOut.Notef("%s", message)
		}
	})
	if errOut.TTY {
		errOut.Print("\r\x1b[2K")
	}
	if err != nil {
		return cligen.TokenResponse{}, oauthError(err)
	}
	errOut.Okf("approved")
	result.Issues = append(result.Issues, auth.Issues...)
	return s.finishToken(ctx, result, issuer, metadata, dpop, p.Save, p.NoVerify, string(p.Format), "")
}

// spaceCode groups a user code for reading aloud.
func spaceCode(code string) string {
	if strings.ContainsAny(code, "- ") || len(code) <= 4 {
		return code
	}
	var b strings.Builder
	for i, r := range code {
		if i > 0 && i%4 == 0 {
			b.WriteRune(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// renderQR draws a URL as a QR code with half-block glyphs, two rows per line.
func renderQR(p *render.Printer, target string) error {
	code, err := qrcode.New(target, qrcode.Medium)
	if err != nil {
		return err
	}
	bitmap := code.Bitmap()
	var b strings.Builder
	for y := 0; y < len(bitmap); y += 2 {
		for x := 0; x < len(bitmap[y]); x++ {
			top := bitmap[y][x]
			bottom := y+1 < len(bitmap) && bitmap[y+1][x]
			switch {
			case top && bottom:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bottom:
				b.WriteString("▄")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString("\n")
	}
	p.Print(b.String())
	return nil
}
