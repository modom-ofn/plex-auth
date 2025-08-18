package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/gorilla/mux"
)

// Use the same client identifier you used before
var plexClientID = "plex-auth-go"

type PinResponse struct {
	ID               int    `json:"id"`
	Code             string `json:"code"`
	AuthToken        string `json:"authToken"`
	ClientIdentifier string `json:"clientIdentifier"`
	QR               string `json:"qr"`
	ExpiresIn        int    `json:"expiresIn"`
	CreatedAt        string `json:"createdAt"`
	ExpiresAt        string `json:"expiresAt"`
}

type TokenResponse struct {
	AuthToken string `json:"authToken"`
	User      struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		UUID     string `json:"uuid"`
	} `json:"user"`
}

// POST /auth/start-web
func startAuthWebHandler(w http.ResponseWriter, r *http.Request) {
	// Create strong PIN (JSON)
	req, err := http.NewRequest("POST", "https://plex.tv/api/v2/pins?strong=true", nil)
	if err != nil {
		http.Error(w, "request init failed", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Plex-Product", "PlexAuth")
	req.Header.Set("X-Plex-Client-Identifier", plexClientID)
	req.Header.Set("X-Plex-Version", "1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "plex unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		http.Error(w, "plex PIN create failed", http.StatusBadGateway)
		return
	}

	var pin struct {
		ID   int    `json:"id"`
		Code string `json:"code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&pin); err != nil {
		http.Error(w, "plex decode failed", http.StatusBadGateway)
		return
	}

	// Persist mapping code→id so we can look it up later (you already implemented savePin)
	_ = savePin(pin.Code, pin.ID)

	// Build the Plex Auth App URL that opens in the popup
	forward := appBaseURL + "/auth/forward?pinId=" + url.QueryEscape(strconv.Itoa(pin.ID)) +
		"&code=" + url.QueryEscape(pin.Code)

	q := url.Values{}
	q.Set("clientID", plexClientID)
	q.Set("code", pin.Code)
	q.Set("forwardUrl", forward)
	q.Set("context[device][product]", "PlexAuth")

	authURL := "https://app.plex.tv/auth#?" + q.Encode()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"authUrl": authURL})
}

// GET /auth/forward
func forwardHandler(w http.ResponseWriter, r *http.Request) {
	pinIDStr := r.URL.Query().Get("pinId")
	code := r.URL.Query().Get("code")
	if pinIDStr == "" || code == "" {
		http.Error(w, "missing params", http.StatusBadRequest)
		return
	}
	pinID, err := strconv.Atoi(pinIDStr)
	if err != nil {
		http.Error(w, "bad pinId", http.StatusBadRequest)
		return
	}

	// Poll quickly for the token
	var tokenResp struct{ AuthToken string `json:"authToken"` }
	ok := false
	for i := 0; i < 6; i++ { // ~9 seconds total
		reqURL := fmt.Sprintf("https://plex.tv/api/v2/pins/%d?code=%s", pinID, url.QueryEscape(code))
		req, _ := http.NewRequest("GET", reqURL, nil)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("X-Plex-Client-Identifier", plexClientID)

		resp, err := http.DefaultClient.Do(req)
		if err == nil && resp != nil && resp.StatusCode == 200 {
			_ = json.NewDecoder(resp.Body).Decode(&tokenResp)
			resp.Body.Close()
			if tokenResp.AuthToken != "" {
				ok = true
				break
			}
		} else if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(1500 * time.Millisecond)
	}

	if ok {
		// Fetch profile, save, and set session cookie so the opener is already logged in
		profile, perr := fetchUserProfile(tokenResp.AuthToken) // you already have this helper
		if perr == nil {
			saveUser(TokenResponse{
				AuthToken: tokenResp.AuthToken,
				User: struct {
					Username string `json:"username"`
					Email    string `json:"email"`
					UUID     string `json:"uuid"`
				}{
					Username: profile.User.Username,
					Email:    profile.User.Email,
					UUID:     profile.User.UUID,
				},
			})
			_ = setSessionCookie(w, profile.User.UUID, profile.User.Username)
		} else {
			ok = false
		}
	}

	// This tiny page needs inline JS to postMessage and close; relax CSP ONLY for this response.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'")

	fmt.Fprintf(w, `<!doctype html>
<meta charset="utf-8">
<title>PlexAuth</title>
<script>
(function(){
  try {
    if (window.opener && window.opener !== window) {
      window.opener.postMessage({type:"plex-auth", ok:%v}, window.location.origin);
    }
  } catch(e){}
  setTimeout(function(){ window.close(); }, 200);
})();
</script>
<body style="background:#0b1020;color:#e5e7eb;font:14px system-ui">
  <p style="text-align:center;margin-top:20vh">You can close this window.</p>
</body>`, ok)
}

func loginPageHandler(w http.ResponseWriter, r *http.Request) {
	render(w, "login.html", map[string]any{
		"BaseURL": appBaseURL,
	})
}

func startAuthHandler(w http.ResponseWriter, r *http.Request) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", "https://plex.tv/pins.xml", nil)
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	req.Header.Set("X-Plex-Product", "PlexAuth")
	req.Header.Set("X-Plex-Version", "1.0")
	req.Header.Set("X-Plex-Client-Identifier", "plex-auth-go")
	req.Header.Set("X-Plex-Device", "Server")
	req.Header.Set("X-Plex-Platform", "Docker")
	req.Header.Set("Accept", "application/xml")

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to contact Plex API", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	type PinXML struct {
		ID   int    `xml:"id"`
		Code string `xml:"code"`
	}

	var pin PinXML
	if err := xml.NewDecoder(resp.Body).Decode(&pin); err != nil {
		http.Error(w, "Failed to parse Plex response", http.StatusInternalServerError)
		return
	}

	_ = savePin(pin.Code, pin.ID)
	log.Printf("PIN created: %s (id=%d)", pin.Code, pin.ID)

	render(w, "link.html", map[string]any{
		"Code":    pin.Code,
		"BaseURL": appBaseURL,
		"LinkURL": "https://plex.tv/link",
	})
}

type accountResponse struct {
	User struct {
		ID       int    `json:"id"`
		UUID     string `json:"uuid"`
		Username string `json:"username"`
		Email    string `json:"email"`
	} `json:"user"`
	AuthToken string `json:"-"`
}

func fetchUserProfile(authToken string) (accountResponse, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("GET", "https://plex.tv/users/account.json", nil)
	req.Header.Set("X-Plex-Token", authToken)
	req.Header.Set("X-Plex-Product", "PlexAuth")
	req.Header.Set("X-Plex-Version", "1.0")
	req.Header.Set("X-Plex-Client-Identifier", "plex-auth-go")
	req.Header.Set("X-Plex-Device", "Server")
	req.Header.Set("X-Plex-Platform", "Docker")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return accountResponse{}, fmt.Errorf("HTTP request failed: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return accountResponse{}, fmt.Errorf("Plex API returned %d: %s", resp.StatusCode, string(body))
	}
	if len(body) > 0 && body[0] == '<' {
		return accountResponse{}, fmt.Errorf("expected JSON but got XML/HTML: %.120s", string(body))
	}

	var profile accountResponse
	if err := json.Unmarshal(body, &profile); err != nil {
		return accountResponse{}, fmt.Errorf("JSON decode failed: %w; body: %s", err, string(body))
	}
	profile.AuthToken = authToken
	return profile, nil
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	code := mux.Vars(r)["pin"]

	// Lookup pin_id from DB
	var pinID int
	if err := db.QueryRow(`SELECT pin_id FROM pins WHERE code = $1`, code).Scan(&pinID); err != nil {
		http.Error(w, "PIN not found or expired", http.StatusBadRequest)
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}

	// Poll for token
	for i := 0; i < 20; i++ {
		time.Sleep(3 * time.Second)

		tokenURL := fmt.Sprintf("https://plex.tv/api/v2/pins/%d", pinID)
		req, _ := http.NewRequest("GET", tokenURL, nil)
		req.Header.Set("X-Plex-Client-Identifier", "plex-auth-go")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var poll struct {
			AuthToken string `json:"authToken"`
		}
		if err := json.Unmarshal(body, &poll); err != nil || poll.AuthToken == "" {
			continue
		}

		// Fetch profile, save user, set session, redirect to /portal
		profile, err := fetchUserProfile(poll.AuthToken)
		if err != nil {
			log.Printf("Failed to fetch user profile: %v", err)
			http.Error(w, "Failed to fetch user info", http.StatusInternalServerError)
			return
		}

		saveUser(TokenResponse{
			AuthToken: poll.AuthToken,
			User: struct {
				Username string `json:"username"`
				Email    string `json:"email"`
				UUID     string `json:"uuid"`
			}{
				Username: profile.User.Username,
				Email:    profile.User.Email,
				UUID:     profile.User.UUID,
			},
		})

		// Issue session cookie and redirect
		if err := setSessionCookie(w, profile.User.UUID, profile.User.Username); err != nil {
			log.Printf("Failed to set session: %v", err)
			http.Error(w, "Session error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/portal", http.StatusFound)
		return
	}

	http.Error(w, "Login timed out", http.StatusRequestTimeout)
}

func portalHandler(w http.ResponseWriter, r *http.Request) {
	username := usernameFrom(r.Context())
	render(w, "portal.html", map[string]any{
		"Username": username,
	})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	clearSessionCookie(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

// ---------- tiny templating helpers + username context ----------

func render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("template %s error: %v", name, err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

type userKey struct{}

func withUsername(ctx context.Context, u string) context.Context {
	return context.WithValue(ctx, userKey{}, u)
}

func usernameFrom(ctx context.Context) string {
	if v := ctx.Value(userKey{}); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// pollAuthHandler checks once if the PIN has produced an auth token.
// If not ready, returns 202. If ready, it saves the user, sets the session cookie, and returns 200 JSON.
func pollAuthHandler(w http.ResponseWriter, r *http.Request) {
	code := mux.Vars(r)["pin"]

	// Lookup pin_id from DB
	var pinID int
	if err := db.QueryRow(`SELECT pin_id FROM pins WHERE code = $1`, code).Scan(&pinID); err != nil {
		http.Error(w, `{"ok":false,"error":"pin_not_found"}`, http.StatusNotFound)
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	tokenURL := fmt.Sprintf("https://plex.tv/api/v2/pins/%d", pinID)
	req, _ := http.NewRequest("GET", tokenURL, nil)
	req.Header.Set("X-Plex-Client-Identifier", "plex-auth-go")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, `{"ok":false,"error":"plex_unreachable"}`, http.StatusBadGateway)
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// Expect {"authToken":"..."} once linked
	var poll struct {
		AuthToken string `json:"authToken"`
	}
	if err := json.Unmarshal(body, &poll); err != nil || poll.AuthToken == "" {
		// Not ready yet
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted) // 202
		_, _ = w.Write([]byte(`{"ok":false,"pending":true}`))
		return
	}

	// Fetch profile, save, set session
	profile, err := fetchUserProfile(poll.AuthToken)
	if err != nil {
		http.Error(w, `{"ok":false,"error":"profile_fetch_failed"}`, http.StatusBadGateway)
		return
	}

	saveUser(TokenResponse{
		AuthToken: poll.AuthToken,
		User: struct {
			Username string `json:"username"`
			Email    string `json:"email"`
			UUID     string `json:"uuid"`
		}{
			Username: profile.User.Username,
			Email:    profile.User.Email,
			UUID:     profile.User.UUID,
		},
	})

	if err := setSessionCookie(w, profile.User.UUID, profile.User.Username); err != nil {
		http.Error(w, `{"ok":false,"error":"session_error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func startAuthJSONHandler(w http.ResponseWriter, r *http.Request) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", "https://plex.tv/pins.xml", nil)
	if err != nil {
		http.Error(w, `{"error":"request_create_failed"}`, http.StatusInternalServerError)
		return
	}

	req.Header.Set("X-Plex-Product", "PlexAuth")
	req.Header.Set("X-Plex-Version", "1.0")
	req.Header.Set("X-Plex-Client-Identifier", "plex-auth-go")
	req.Header.Set("X-Plex-Device", "Server")
	req.Header.Set("X-Plex-Platform", "Docker")
	req.Header.Set("Accept", "application/xml")

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, `{"error":"plex_unreachable"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	type PinXML struct {
		ID   int    `xml:"id"`
		Code string `xml:"code"`
	}
	var pin PinXML
	if err := xml.NewDecoder(resp.Body).Decode(&pin); err != nil {
		http.Error(w, `{"error":"plex_parse_failed"}`, http.StatusInternalServerError)
		return
	}
	_ = savePin(pin.Code, pin.ID)
	log.Printf("PIN created (JSON): %s (id=%d)", pin.Code, pin.ID)

	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, fmt.Sprintf(`{"code":"%s","linkUrl":"https://plex.tv/link","pollUrl":"%s/auth/poll/%s"}`, pin.Code, appBaseURL, pin.Code))
}