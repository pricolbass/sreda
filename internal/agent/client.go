package agent

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sreda/internal/agentprotocol"
	"strings"
	"time"
)

type State struct {
	Origin      string                `json:"origin"`
	PrivateKey  string                `json:"private_key"`
	PublicKey   string                `json:"public_key"`
	Credential  string                `json:"credential"`
	PendingCode string                `json:"pending_code,omitempty"`
	Control     agentprotocol.Control `json:"control"`
}

func validateOrigin(origin string) error {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("нужен HTTPS-адрес кабинета без пути")
	}
	return nil
}
func statePath(dir string) string { return filepath.Join(dir, "state.json") }
func LoadState(dir string) (State, error) {
	var s State
	data, err := os.ReadFile(statePath(dir))
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(data, &s)
	if err != nil {
		return s, errors.New("повреждено состояние агента")
	}
	if err = validateOrigin(s.Origin); err != nil {
		return s, err
	}
	if len(s.Credential) != 43 {
		return s, errors.New("повреждены учётные данные агента")
	}
	return s, nil
}
func saveState(dir string, s State) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return err
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".state-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, statePath(dir)); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// ProtocolError exposes only the HTTP status, never secret-bearing response bodies.
type ProtocolError struct{ Status int }

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("кабинет отверг запрос (HTTP %d)", e.Status)
}
func exchange(ctx context.Context, client *http.Client, origin, path, credential string, input any) (agentprotocol.Control, error) {
	var control agentprotocol.Control
	data, err := json.Marshal(input)
	if err != nil {
		return control, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", origin+path, bytes.NewReader(data))
	if err != nil {
		return control, err
	}
	req.Header.Set("Content-Type", "application/json")
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	// Redirects must not forward credentials or enroll a different endpoint.
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := copyClient.Do(req)
	if err != nil {
		return control, errors.New("не удалось связаться с кабинетом по HTTPS")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 && response.StatusCode != 201 {
		return control, &ProtocolError{Status: response.StatusCode}
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	if err = decoder.Decode(&control); err != nil {
		return control, errors.New("некорректный ответ кабинета")
	}
	return control, nil
}
func defaultClient(client *http.Client) *http.Client {
	if client != nil {
		return client
	}
	return &http.Client{Timeout: 20 * time.Second}
}

// Enroll persists generated secrets before consuming the code, permitting safe recovery
// when the enrollment response is lost. It does not claim tunnel connectivity.
func Enroll(ctx context.Context, dir, origin, code string, client *http.Client) (State, error) {
	var state State
	origin = strings.TrimSuffix(origin, "/")
	if err := validateOrigin(origin); err != nil {
		return state, err
	}
	if len(code) != 43 {
		return state, errors.New("неверный код подключения")
	}
	client = defaultClient(client)
	existing, err := LoadState(dir)
	if err == nil {
		state = existing
		if state.Origin != origin {
			return state, errors.New("состояние принадлежит другому кабинету")
		}
		if state.PendingCode == "" {
			return state, errors.New("агент уже зарегистрирован; переподключение создаётся в кабинете")
		}
		if state.PendingCode != code {
			return state, errors.New("незавершённое подключение использует другой код; сохраните состояние и проверьте запись машины")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return state, err
	} else {
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return state, err
		}
		credential := make([]byte, 32)
		if _, err = rand.Read(credential); err != nil {
			return state, err
		}
		state = State{Origin: origin, PrivateKey: base64.StdEncoding.EncodeToString(key.Bytes()), PublicKey: base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), Credential: base64.RawURLEncoding.EncodeToString(credential), PendingCode: code}
		if err = saveState(dir, state); err != nil {
			return state, err
		}
	}
	input := struct {
		Code       string `json:"code"`
		PublicKey  string `json:"public_key"`
		Credential string `json:"credential"`
	}{code, state.PublicKey, state.Credential}
	control, err := exchange(ctx, client, origin, "/api/agent/enroll", "", input)
	if err != nil {
		var protocolErr *ProtocolError
		if errors.As(err, &protocolErr) && protocolErr.Status == 401 {
			control, err = heartbeat(ctx, client, state, false)
		}
	}
	if err != nil {
		return state, err
	}
	if err = validateControl(control); err != nil {
		return state, err
	}
	state.Control = control
	state.PendingCode = ""
	if err = saveState(dir, state); err != nil {
		return state, err
	}
	return state, nil
}

type routeAcknowledgment struct {
	Ready             bool   `json:"ready"`
	AppliedGeneration uint64 `json:"applied_generation"`
	FailedGeneration  uint64 `json:"failed_generation,omitempty"`
	ApplyError        string `json:"apply_error,omitempty"`
}

func heartbeat(ctx context.Context, client *http.Client, s State, ready bool) (agentprotocol.Control, error) {
	return heartbeatAcknowledgment(ctx, client, s, routeAcknowledgment{Ready: ready, AppliedGeneration: s.Control.Generation})
}
func heartbeatAcknowledgment(ctx context.Context, client *http.Client, s State, ack routeAcknowledgment) (agentprotocol.Control, error) {
	return exchange(ctx, client, s.Origin, "/api/agent/heartbeat", s.Credential, ack)
}
