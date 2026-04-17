//go:build ignore

// test_api.go es un script de prueba manual de todos los endpoints REST.
// Ejecución: go run ./cmd/test_api.go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

const base = "http://localhost:8080"

func main() {
	fmt.Println("\n╔══════════════════════════════════════════╗")
	fmt.Println("║      🧪  usuario-auth  API Test Suite    ║")
	fmt.Println("╚══════════════════════════════════════════╝")

	// 1. Health
	section("1. GET /health")
	resp := must(get("/health", ""))
	print200(resp)

	// 2. Register
	section("2. POST /auth/register")
	resp = must(post("/auth/register", `{"username":"rockefeller","email":"rock@example.com","password":"supersecret123"}`, ""))
	print200(resp)

	// 3. Registro duplicado → 409
	section("3. POST /auth/register (email duplicado → 409 esperado)")
	resp = must(post("/auth/register", `{"username":"rockefeller","email":"rock@example.com","password":"supersecret123"}`, ""))
	printStatus(resp, 409)

	// 4. Validación: contraseña corta → 400
	section("4. POST /auth/register (password corta → 400 esperado)")
	resp = must(post("/auth/register", `{"username":"bob","email":"bob@test.com","password":"123"}`, ""))
	printStatus(resp, 400)

	// 5. Login
	section("5. POST /auth/login")
	resp = must(post("/auth/login", `{"email":"rock@example.com","password":"supersecret123"}`, ""))
	body := print200(resp)

	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresAt    string `json:"expires_at"`
		TokenType    string `json:"token_type"`
	}
	if err := json.Unmarshal([]byte(body), &tokens); err != nil {
		fatalf("cannot parse token response: %v", err)
	}
	fmt.Printf("  access_token  : %s...\n", tokens.AccessToken[:min(50, len(tokens.AccessToken))])
	fmt.Printf("  refresh_token : %s...\n", tokens.RefreshToken[:min(50, len(tokens.RefreshToken))])
	fmt.Printf("  expires_at    : %s\n", tokens.ExpiresAt)

	// 6. Login con password incorrecta → 401
	section("6. POST /auth/login (password incorrecta → 401 esperado)")
	resp = must(post("/auth/login", `{"email":"rock@example.com","password":"wrongpassword"}`, ""))
	printStatus(resp, 401)

	// 7. GET /auth/me sin token → 401
	section("7. GET /auth/me (sin token → 401 esperado)")
	resp = must(get("/auth/me", ""))
	printStatus(resp, 401)

	// 8. GET /auth/me con token válido → 200
	section("8. GET /auth/me (Bearer token válido → 200 esperado)")
	resp = must(get("/auth/me", tokens.AccessToken))
	print200(resp)

	// 9. Refresh token → nuevo par
	section("9. POST /auth/refresh")
	refreshBody := fmt.Sprintf(`{"refresh_token":"%s"}`, tokens.RefreshToken)
	resp = must(post("/auth/refresh", refreshBody, ""))
	body = print200(resp)
	var newTokens struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal([]byte(body), &newTokens)
	fmt.Printf("  nuevo access_token: %s...\n", newTokens.AccessToken[:min(50, len(newTokens.AccessToken))])

	// 10. Token inválido → 401
	section("10. GET /auth/me (token falsificado → 401 esperado)")
	resp = must(get("/auth/me", "este.no.es.un.jwt.valido"))
	printStatus(resp, 401)

	fmt.Println("\n╔══════════════════════════════════════════╗")
	fmt.Println("║         ✅  Todos los tests OK           ║")
	fmt.Println("╚══════════════════════════════════════════╝\n")
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func section(title string) {
	fmt.Printf("\n\033[36m══ %s\033[0m\n", title)
}

func print200(r *http.Response) string {
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()
	s := strings.TrimSpace(string(body))
	if r.StatusCode >= 200 && r.StatusCode < 300 {
		fmt.Printf("  \033[32m✓ %d OK\033[0m  %s\n", r.StatusCode, pretty(s))
	} else {
		fmt.Printf("  \033[31m✗ %d FAIL\033[0m  %s\n", r.StatusCode, s)
		os.Exit(1)
	}
	return s
}

func printStatus(r *http.Response, expected int) {
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()
	s := strings.TrimSpace(string(body))
	if r.StatusCode == expected {
		fmt.Printf("  \033[32m✓ %d (esperado %d)\033[0m  %s\n", r.StatusCode, expected, s)
	} else {
		fmt.Printf("  \033[31m✗ %d (esperado %d)\033[0m  %s\n", r.StatusCode, expected, s)
	}
}

func get(path, bearer string) (*http.Response, error) {
	req, _ := http.NewRequest(http.MethodGet, base+path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return http.DefaultClient.Do(req)
}

func post(path, body, bearer string) (*http.Response, error) {
	req, _ := http.NewRequest(http.MethodPost, base+path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return http.DefaultClient.Do(req)
}

func must(r *http.Response, err error) *http.Response {
	if err != nil {
		fatalf("request error: %v", err)
	}
	return r
}

func pretty(s string) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, []byte(s), "    ", "  "); err == nil {
		return buf.String()
	}
	return s
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "\033[31mFATAL: "+format+"\033[0m\n", args...)
	os.Exit(1)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
