package conformance

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Southclaws/oauthcli/internal/jose"
)

// fakeAS is an in-process authorization server with enough behaviour to
// exercise every check that credentials unlock. Its knobs make it conformant
// or deliberately broken.
type fakeAS struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string

	mu      sync.Mutex
	revoked map[string]bool
	issued  map[string]bool
	clients map[string]string

	// Knobs.
	omitNoStore     bool
	plainPKCE       bool
	openRedirect    bool
	leakPrivateKey  bool
	acceptAnyGrant  bool
	ignoreResource  bool
	noIntrospection bool
	nonce           string
}

func newFakeAS() *fakeAS {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	f := &fakeAS{
		key:     key,
		kid:     "test-key",
		revoked: map[string]bool{},
		issued:  map[string]bool{},
		clients: map[string]string{"app": "s3cret"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", f.metadata)
	mux.HandleFunc("/.well-known/openid-configuration", f.metadata)
	mux.HandleFunc("/jwks", f.jwks)
	mux.HandleFunc("/authorize", f.authorize)
	mux.HandleFunc("/token", f.token)
	mux.HandleFunc("/introspect", f.introspect)
	mux.HandleFunc("/revoke", f.revoke)
	mux.HandleFunc("/device", f.device)
	mux.HandleFunc("/par", f.par)
	mux.HandleFunc("/userinfo", f.userinfo)
	mux.HandleFunc("/register", f.register)
	mux.HandleFunc("/register/", f.manage)
	f.server = httptest.NewServer(mux)
	return f
}

func (f *fakeAS) issuer() string { return f.server.URL }

func (f *fakeAS) writeJSON(w http.ResponseWriter, status int, document any) {
	w.Header().Set("Content-Type", "application/json")
	if !f.omitNoStore {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(document)
}

func (f *fakeAS) oauthError(w http.ResponseWriter, status int, code, description string) {
	f.writeJSON(w, status, map[string]any{"error": code, "error_description": description})
}

func (f *fakeAS) metadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	methods := []string{"S256"}
	if f.plainPKCE {
		methods = append(methods, "plain")
	}
	document := map[string]any{
		"issuer":                                         f.issuer(),
		"authorization_endpoint":                         f.issuer() + "/authorize",
		"token_endpoint":                                 f.issuer() + "/token",
		"jwks_uri":                                       f.issuer() + "/jwks",
		"revocation_endpoint":                            f.issuer() + "/revoke",
		"device_authorization_endpoint":                  f.issuer() + "/device",
		"pushed_authorization_request_endpoint":          f.issuer() + "/par",
		"userinfo_endpoint":                              f.issuer() + "/userinfo",
		"registration_endpoint":                          f.issuer() + "/register",
		"scopes_supported":                               []string{"openid", "read", "write"},
		"response_types_supported":                       []string{"code", "id_token", "id_token token"},
		"grant_types_supported":                          []string{"authorization_code", "implicit", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code", "urn:ietf:params:oauth:grant-type:token-exchange"},
		"token_endpoint_auth_methods_supported":          []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":               methods,
		"subject_types_supported":                        []string{"public"},
		"id_token_signing_alg_values_supported":          []string{"RS256"},
		"dpop_signing_alg_values_supported":              []string{"ES256"},
		"authorization_response_iss_parameter_supported": true,
	}
	if !f.noIntrospection {
		document["introspection_endpoint"] = f.issuer() + "/introspect"
	}
	f.writeJSON(w, 200, document)
}

func (f *fakeAS) jwks(w http.ResponseWriter, r *http.Request) {
	var key *jose.JWK
	if f.leakPrivateKey {
		key, _ = jose.PrivateJWK(f.key)
	} else {
		key, _ = jose.PublicJWK(&f.key.PublicKey)
	}
	key.Kid = f.kid
	key.Alg = "RS256"
	key.Use = "sig"
	w.Header().Set("Cache-Control", "max-age=3600")
	f.writeJSON(w, 200, map[string]any{"keys": []any{key}})
}

func (f *fakeAS) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect := q.Get("redirect_uri")
	if q.Get("client_id") == "" {
		http.Error(w, "missing client_id", 400)
		return
	}
	registered := strings.HasPrefix(redirect, "http://127.0.0.1") && (f.openRedirect || !strings.Contains(redirect, "open-redirect-probe"))
	if !registered {
		http.Error(w, "unregistered redirect_uri", 400)
		return
	}
	target, _ := url.Parse(redirect)
	values := target.Query()
	values.Set("state", q.Get("state"))
	switch {
	case q.Get("response_type") != "code":
		values.Set("error", "unsupported_response_type")
	case q.Get("code_challenge") == "":
		values.Set("error", "invalid_request")
		values.Set("error_description", "code_challenge is required")
	case q.Get("code_challenge_method") != "" && q.Get("code_challenge_method") != "S256" && !(q.Get("code_challenge_method") == "plain" && f.plainPKCE):
		values.Set("error", "invalid_request")
	default:
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>login page</html>"))
		return
	}
	target.RawQuery = values.Encode()
	http.Redirect(w, r, target.String(), 302)
}

func (f *fakeAS) authenticate(r *http.Request) (string, bool) {
	if id, secret, ok := r.BasicAuth(); ok {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
		return id, f.clients[id] == secret
	}
	id := r.PostFormValue("client_id")
	if secret := r.PostFormValue("client_secret"); secret != "" {
		return id, f.clients[id] == secret
	}
	return id, id != "" && f.clients[id] == ""
}

func (f *fakeAS) mint(clientID, scope, jkt string, ttl time.Duration) string {
	now := time.Now()
	claims := map[string]any{
		"iss": f.issuer(), "sub": clientID, "aud": "https://api.example.com", "client_id": clientID,
		"iat": now.Unix(), "exp": now.Add(ttl).Unix(), "jti": jose.RandomString(8), "scope": scope,
	}
	if jkt != "" {
		claims["cnf"] = map[string]any{"jkt": jkt}
	}
	token, _ := jose.Sign(map[string]any{"typ": "at+jwt", "kid": f.kid}, claims, f.key, "RS256")
	f.mu.Lock()
	f.issued[token] = true
	f.mu.Unlock()
	return token
}

func (f *fakeAS) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	if err := r.ParseForm(); err != nil || len(r.PostForm) == 0 {
		f.oauthError(w, 400, "invalid_request", "no parameters")
		return
	}
	for name, values := range r.PostForm {
		if len(values) > 1 && name != "resource" {
			f.oauthError(w, 400, "invalid_request", "parameter "+name+" repeated")
			return
		}
	}
	clientID, ok := f.authenticate(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
		f.oauthError(w, 401, "invalid_client", "bad credentials")
		return
	}
	scope := r.PostFormValue("scope")
	for _, s := range strings.Fields(scope) {
		if s == "oauthcli:scope:does-not-exist" {
			f.oauthError(w, 400, "invalid_scope", "unknown scope")
			return
		}
	}
	if resource := r.PostFormValue("resource"); resource != "" && !f.ignoreResource && strings.Contains(resource, "invalid") {
		f.oauthError(w, 400, "invalid_target", "unknown resource")
		return
	}
	jkt := ""
	tokenType := "Bearer"
	if proof := r.Header.Get("DPoP"); proof != "" {
		if f.nonce != "" {
			parsed, _ := jose.Parse(proof)
			if parsed == nil || parsed.String("nonce") != f.nonce {
				w.Header().Set("DPoP-Nonce", f.nonce)
				f.oauthError(w, 400, "use_dpop_nonce", "nonce required")
				return
			}
		}
		parsed, err := jose.Parse(proof)
		if err == nil && parsed.String("htu") != f.issuer()+"/token" {
			f.oauthError(w, 400, "invalid_dpop_proof", "htu does not match")
			return
		}
		if err == nil {
			raw, _ := json.Marshal(parsed.Header["jwk"])
			var jwk jose.JWK
			json.Unmarshal(raw, &jwk)
			jkt, _ = jwk.Thumbprint()
			tokenType = "DPoP"
		}
	}
	switch r.PostFormValue("grant_type") {
	case "client_credentials":
		f.writeJSON(w, 200, map[string]any{"access_token": f.mint(clientID, scope, jkt, time.Hour), "token_type": tokenType, "expires_in": 3600, "scope": scope})
	case "refresh_token":
		f.writeJSON(w, 200, map[string]any{"access_token": f.mint(clientID, scope, jkt, time.Hour), "token_type": tokenType, "expires_in": 3600, "refresh_token": "rotated-" + jose.RandomString(4)})
	case "urn:ietf:params:oauth:grant-type:device_code":
		f.oauthError(w, 400, "authorization_pending", "waiting")
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		f.mu.Lock()
		known := f.issued[r.PostFormValue("subject_token")]
		f.mu.Unlock()
		if !known {
			f.oauthError(w, 400, "invalid_request", "subject_token is not usable")
			return
		}
		f.writeJSON(w, 200, map[string]any{"access_token": f.mint(clientID, scope, "", time.Hour), "token_type": "Bearer", "issued_token_type": "urn:ietf:params:oauth:token-type:access_token", "expires_in": 3600})
	default:
		if f.acceptAnyGrant {
			f.writeJSON(w, 200, map[string]any{"access_token": f.mint(clientID, scope, "", time.Hour), "token_type": "Bearer", "expires_in": 3600})
			return
		}
		f.oauthError(w, 400, "unsupported_grant_type", "no")
	}
}

func (f *fakeAS) introspect(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if _, ok := f.authenticate(r); !ok || r.PostFormValue("client_id") == "" && r.Header.Get("Authorization") == "" {
		f.oauthError(w, 401, "invalid_client", "authenticate")
		return
	}
	token := r.PostFormValue("token")
	f.mu.Lock()
	active := f.issued[token] && !f.revoked[token]
	f.mu.Unlock()
	if !active {
		f.writeJSON(w, 200, map[string]any{"active": false})
		return
	}
	parsed, _ := jose.Parse(token)
	f.writeJSON(w, 200, map[string]any{"active": true, "client_id": parsed.String("client_id"), "exp": parsed.Claims["exp"], "scope": parsed.String("scope"), "sub": parsed.String("sub")})
}

func (f *fakeAS) revoke(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if _, ok := f.authenticate(r); !ok {
		f.oauthError(w, 401, "invalid_client", "authenticate")
		return
	}
	f.mu.Lock()
	f.revoked[r.PostFormValue("token")] = true
	f.mu.Unlock()
	w.WriteHeader(200)
}

func (f *fakeAS) device(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if _, ok := f.authenticate(r); !ok {
		f.oauthError(w, 401, "invalid_client", "authenticate")
		return
	}
	f.writeJSON(w, 200, map[string]any{
		"device_code": "dev-" + jose.RandomString(8), "user_code": "ABCD-EFGH",
		"verification_uri": f.issuer() + "/device/verify", "verification_uri_complete": f.issuer() + "/device/verify?user_code=ABCD-EFGH",
		"expires_in": 600, "interval": 5,
	})
}

func (f *fakeAS) par(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if r.PostFormValue("request_uri") != "" {
		f.oauthError(w, 400, "invalid_request", "request_uri not allowed")
		return
	}
	if _, ok := f.authenticate(r); !ok {
		f.oauthError(w, 401, "invalid_client", "authenticate")
		return
	}
	f.writeJSON(w, 201, map[string]any{"request_uri": "urn:ietf:params:oauth:request_uri:" + jose.RandomString(8), "expires_in": 90})
}

func (f *fakeAS) userinfo(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	token := strings.TrimPrefix(strings.TrimPrefix(auth, "Bearer "), "DPoP ")
	if auth == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo"`)
		w.WriteHeader(401)
		return
	}
	f.mu.Lock()
	active := f.issued[token] && !f.revoked[token]
	f.mu.Unlock()
	if !active {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		w.WriteHeader(401)
		return
	}
	parsed, _ := jose.Parse(token)
	f.writeJSON(w, 200, map[string]any{"sub": parsed.String("sub")})
}

func (f *fakeAS) register(w http.ResponseWriter, r *http.Request) {
	var document map[string]any
	if err := json.NewDecoder(r.Body).Decode(&document); err != nil {
		f.oauthError(w, 400, "invalid_client_metadata", "bad json")
		return
	}
	if _, ok := document["redirect_uris"].([]any); !ok {
		f.oauthError(w, 400, "invalid_redirect_uri", "redirect_uris must be an array")
		return
	}
	id := "dyn-" + jose.RandomString(6)
	f.mu.Lock()
	f.clients[id] = ""
	f.mu.Unlock()
	document["client_id"] = id
	document["client_id_issued_at"] = time.Now().Unix()
	document["registration_client_uri"] = f.issuer() + "/register/" + id
	document["registration_access_token"] = "rat-" + id
	f.writeJSON(w, 201, document)
}

func (f *fakeAS) manage(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/register/")
	f.mu.Lock()
	_, exists := f.clients[id]
	f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer rat-"+id || !exists {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		f.oauthError(w, 401, "invalid_token", "bad registration token")
		return
	}
	switch r.Method {
	case http.MethodGet:
		f.writeJSON(w, 200, map[string]any{"client_id": id, "redirect_uris": []string{"http://127.0.0.1/oauthcli-callback"}})
	case http.MethodDelete:
		f.mu.Lock()
		delete(f.clients, id)
		f.mu.Unlock()
		w.WriteHeader(204)
	default:
		w.WriteHeader(405)
	}
}
