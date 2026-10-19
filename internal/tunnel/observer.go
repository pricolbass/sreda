package tunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type handshakeResult struct {
	Latest int64 `json:"latest_handshake"`
}

func (c *Client) LatestHandshake(ctx context.Context, peer Peer) (time.Time, error) {
	body, err := json.Marshal(peer)
	if err != nil {
		return time.Time{}, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", "http://network/peers/observe", bytes.NewReader(body))
	if err != nil {
		return time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return time.Time{}, errors.New("контакт WireGuard не подтверждён")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, errors.New("контакт WireGuard не подтверждён")
	}
	var result handshakeResult
	dec := json.NewDecoder(io.LimitReader(resp.Body, 1024))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&result); err != nil || dec.Decode(new(any)) != io.EOF {
		return time.Time{}, errors.New("наблюдение WireGuard недоступно")
	}
	return handshakeTime(result.Latest)
}

func handshakeTime(epoch int64) (time.Time, error) {
	if epoch == 0 {
		return time.Time{}, nil
	}
	if epoch < 0 || epoch > time.Now().Add(5*time.Second).Unix() {
		return time.Time{}, errors.New("некорректное время контакта WireGuard")
	}
	return time.Unix(epoch, 0), nil
}

func (h *Helper) observe(ctx context.Context, peer Peer) (time.Time, error) {
	if err := h.checkPolicy(ctx); err != nil {
		return time.Time{}, err
	}
	allowed, err := h.hasClient(ctx, peer)
	if err != nil || !allowed {
		return time.Time{}, errors.New("peer is not enabled")
	}
	address, err := h.peerAddress(ctx, peer.PublicKey)
	if err != nil || address != peer.Address {
		return time.Time{}, errors.New("peer is not configured")
	}
	out, err := h.runner.Run(ctx, h.config.WG, []string{"show", h.config.Interface, "latest-handshakes"}, "")
	if err != nil {
		return time.Time{}, err
	}
	found := false
	var epoch int64
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 {
			return time.Time{}, errors.New("invalid handshake state")
		}
		if fields[0] != peer.PublicKey {
			continue
		}
		if found {
			return time.Time{}, errors.New("duplicate handshake state")
		}
		epoch, err = strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return time.Time{}, err
		}
		found = true
	}
	if !found {
		return time.Time{}, errors.New("handshake state missing")
	}
	return handshakeTime(epoch)
}
