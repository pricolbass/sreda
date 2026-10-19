package tunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"
)

// Client speaks only to the root-managed Unix socket. Filesystem ownership is
// its authorization boundary; it never sends commands to an Internet endpoint.
type Client struct {
	http    *http.Client
	details Details
}

func NewClient(socket string, details Details) *Client {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socket)
	}}
	return &Client{http: &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, details: details}
}
func (c *Client) Details() Details                               { return c.details }
func (c *Client) ApplyPeer(ctx context.Context, peer Peer) error { return c.change(ctx, "apply", peer) }
func (c *Client) RemovePeer(ctx context.Context, peer Peer) error {
	return c.change(ctx, "remove", peer)
}
func (c *Client) change(ctx context.Context, action string, peer Peer) error {
	body, err := json.Marshal(peer)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", "http://network/peers/"+action, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(req)
	if err != nil {
		return errors.New("сетевое изменение не подтверждено: helper недоступен")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return errors.New("сетевое изменение не подтверждено")
	}
	return nil
}
