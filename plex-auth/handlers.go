package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

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

func startAuthHandler(w http.ResponseWriter, r *http.Request) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", "https://plex.tv/pins.xml", nil)
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	// Required Plex headers
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
	fmt.Fprintf(w, "Visit https://plex.tv/link and enter code: %s\n", pin.Code)
	fmt.Fprintf(w, "Then call http://localhost:8089/auth/callback/%s to complete login.\n", pin.Code)
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

	// Force JSON with .json and include all Plex headers
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

	if resp.StatusCode != 200 {
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

	// Lookup stored pin_id from DB
	var pinID int
	if err := db.QueryRow(`SELECT pin_id FROM pins WHERE code = $1`, code).Scan(&pinID); err != nil {
		http.Error(w, "PIN not found or expired", http.StatusBadRequest)
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}

	// Poll for authToken
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

		if len(body) == 0 || string(body) == "{}" {
			continue
		}

		// The poll response contains only authToken at top-level.
		var poll struct {
			AuthToken string `json:"authToken"`
		}
		if err := json.Unmarshal(body, &poll); err != nil {
			log.Printf("PIN poll JSON error: %v; body=%s", err, string(body))
			continue
		}
		if poll.AuthToken == "" {
			continue
		}

		// Fetch user profile using the token
		profile, err := fetchUserProfile(poll.AuthToken)
		if err != nil {
			log.Printf("Failed to fetch user profile: %v", err)
			http.Error(w, "Failed to fetch user info", http.StatusInternalServerError)
			return
		}

		// Map into your TokenResponse shape so saveUser(...) stays the same
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

		fmt.Fprintf(w, "Login complete! Welcome, %s\n", profile.User.Username)
		return
	}

	http.Error(w, "Login timed out", http.StatusRequestTimeout)
}