package tunnel

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Runner is the boundary to the Linux kernel tools, not a shell.
type Runner interface {
	Run(context.Context, string, []string, string) (string, error)
}
type CommandRunner struct{}

func (CommandRunner) Run(ctx context.Context, name string, args []string, input string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(input)
	// Tool output may contain topology. Errors returned over HTTP are deliberately generic.
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s failed: %w", filepath.Base(name), err)
	}
	return string(output), nil
}

type HelperConfig struct{ Interface, WG, NFT, IP string }
type Helper struct {
	config      HelperConfig
	runner      Runner
	mu          sync.Mutex
	initialized bool
	policy      string
}

var interfaceName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,15}$`)

func NewHelper(config HelperConfig, runner Runner) (*Helper, error) {
	if config.IP == "" {
		config.IP = "/usr/sbin/ip"
	}
	if !interfaceName.MatchString(config.Interface) || !filepath.IsAbs(config.WG) || !filepath.IsAbs(config.NFT) || !filepath.IsAbs(config.IP) || runner == nil {
		return nil, errors.New("invalid network helper configuration")
	}
	return &Helper{config: config, runner: runner}, nil
}

// Initialize installs the deny policy BEFORE a listener accepts mutations. It
// intentionally forgets allowed clients on helper restart; the application must
// replay enabled peers. No FORWARD or gateway INPUT exception is client-owned.
func (h *Helper) Initialize(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.initialize(ctx)
}
func (h *Helper) initialize(ctx context.Context) error {
	if h.initialized {
		return nil
	}
	prefix := ""
	if _, err := h.runner.Run(ctx, h.config.NFT, []string{"list", "table", "inet", "sreda"}, ""); err == nil {
		prefix = "delete table inet sreda\n"
	}
	rules := prefix + fmt.Sprintf(`table inet sreda {
 set clients { type ipv4_addr; }
 chain input { type filter hook input priority -10; policy accept;
  iifname "%s" ip saddr @clients ct direction reply ct state established accept
  iifname "%s" drop
 }
 chain forward { type filter hook forward priority -10; policy accept;
  iifname "%s" drop
  oifname "%s" drop
 }
 chain output { type filter hook output priority -10; policy accept;
  oifname "%s" ip daddr @clients accept
  oifname "%s" drop
 }
}
`, h.config.Interface, h.config.Interface, h.config.Interface, h.config.Interface, h.config.Interface, h.config.Interface)
	if _, err := h.runner.Run(ctx, h.config.NFT, []string{"-f", "-"}, rules); err != nil {
		return errors.New("network isolation not confirmed")
	}
	policy, err := h.readPolicy(ctx)
	if err != nil {
		return errors.New("network isolation not confirmed")
	}
	h.policy = policy
	h.initialized = true
	return nil
}

func validatePeer(peer Peer) error {
	key, err := base64.StdEncoding.DecodeString(peer.PublicKey)
	if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != peer.PublicKey || strings.Trim(string(key), "\x00") == "" {
		return errors.New("invalid public key")
	}
	// One /32 per machine. Never allow a client to claim the gateway or a subnet.
	if peer.MachineID < 1 {
		return errors.New("invalid machine")
	}
	prefix, err := netip.ParsePrefix(peer.Address)
	if err != nil || prefix.String() != peer.Address || !prefix.Addr().Is4() || prefix.Bits() != 32 {
		return errors.New("invalid client address")
	}
	address := prefix.Addr().As4()
	if address[0] != 10 || address[1] != 203 || address[2] != 0 || address[3] < 2 || address[3] > 101 {
		return errors.New("invalid client address")
	}
	return nil
}

func (h *Helper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	if r.URL.Path != "/peers/apply" && r.URL.Path != "/peers/remove" {
		http.NotFound(w, r)
		return
	}
	var peer Peer
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&peer); err != nil {
		http.Error(w, "invalid peer", 400)
		return
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		http.Error(w, "invalid request", 400)
		return
	}
	if err := validatePeer(peer); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := h.initialize(ctx); err != nil {
		http.Error(w, "network isolation not confirmed", 503)
		return
	}
	var err error
	if r.URL.Path == "/peers/apply" {
		err = h.apply(ctx, peer)
	} else {
		err = h.remove(ctx, peer)
	}
	if err != nil {
		http.Error(w, "network change not confirmed", 503)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Helper) hasClient(ctx context.Context, peer Peer) (bool, error) {
	// JSON avoids matching a substring of a different address. Any unreadable
	// firewall state fails closed; callers must not interpret it as absence.
	out, err := h.runner.Run(ctx, h.config.NFT, []string{"-j", "list", "set", "inet", "sreda", "clients"}, "")
	if err != nil {
		return false, err
	}
	var doc struct {
		NFTables []struct {
			Set *struct {
				Name string            `json:"name"`
				Elem []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return false, err
	}
	address := strings.TrimSuffix(peer.Address, "/32")
	for _, item := range doc.NFTables {
		if item.Set != nil && item.Set.Name == "clients" {
			for _, elem := range item.Set.Elem {
				var value string
				if json.Unmarshal(elem, &value) != nil {
					return false, errors.New("unexpected firewall element")
				}
				if value == address {
					return true, nil
				}
			}
			return false, nil
		}
	}
	return false, errors.New("firewall set missing")
}
func (h *Helper) setClient(ctx context.Context, peer Peer, allowed bool) error {
	present, err := h.hasClient(ctx, peer)
	if err != nil {
		return err
	}
	if present == allowed {
		return nil
	}
	action := "delete"
	if allowed {
		action = "add"
	}
	input := fmt.Sprintf("%s element inet sreda clients { %s }\n", action, strings.TrimSuffix(peer.Address, "/32"))
	if _, err := h.runner.Run(ctx, h.config.NFT, []string{"-f", "-"}, input); err != nil {
		return err
	}
	present, err = h.hasClient(ctx, peer)
	if err != nil {
		return err
	}
	if present != allowed {
		return errors.New("firewall change not confirmed")
	}
	return nil
}
func (h *Helper) peerAddress(ctx context.Context, key string) (string, error) {
	out, err := h.runner.Run(ctx, h.config.WG, []string{"show", h.config.Interface, "allowed-ips"}, "")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == key {
			if len(fields) != 2 {
				return "", errors.New("invalid peer state")
			}
			return fields[1], nil
		}
	}
	return "", nil
}
func (h *Helper) apply(ctx context.Context, peer Peer) error {
	if err := h.checkRoute(ctx, peer); err != nil {
		return err
	}
	if err := h.checkPolicy(ctx); err != nil {
		return err
	}
	// A repeated apply must not steal an address from a different public key.
	out, err := h.runner.Run(ctx, h.config.WG, []string{"show", h.config.Interface, "allowed-ips"}, "")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] != peer.PublicKey && fields[1] == peer.Address {
			return errors.New("address already assigned")
		}
	}
	saved, err := h.peerAddress(ctx, peer.PublicKey)
	if err != nil {
		return err
	}
	if saved != "" && saved != peer.Address {
		return errors.New("public key already assigned")
	}
	allowed, err := h.hasClient(ctx, peer)
	if err != nil {
		return err
	}
	if saved == peer.Address && allowed {
		return nil
	}
	if err := h.setClient(ctx, peer, false); err != nil {
		return err
	}
	if _, err := h.runner.Run(ctx, h.config.WG, []string{"set", h.config.Interface, "peer", peer.PublicKey, "allowed-ips", peer.Address}, ""); err != nil {
		return err
	}
	saved, err = h.peerAddress(ctx, peer.PublicKey)
	if err != nil || saved != peer.Address {
		return errors.New("peer application not confirmed")
	}
	if err := h.setClient(ctx, peer, true); err != nil {
		h.denyAfterError(peer)
		return err
	}
	if err := h.checkPolicy(ctx); err != nil {
		h.denyAfterError(peer)
		return err
	}
	return nil
}

// A failed readback after opening must not leave an unconfirmed client open.
// The caller's context can already be cancelled, so cleanup has its own bound.
func (h *Helper) denyAfterError(peer Peer) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = h.setClient(ctx, peer, false)
	_, _ = h.runner.Run(ctx, h.config.WG, []string{"set", h.config.Interface, "peer", peer.PublicKey, "remove"}, "")
}

func (h *Helper) checkPolicy(ctx context.Context) error {
	policy, err := h.readPolicy(ctx)
	if err != nil || policy != h.policy {
		return errors.New("network isolation not confirmed")
	}
	return nil
}

// Capture the complete installed table after our atomic installation and reject
// subsequent drift, including missing rules, changed hooks or added accepts.
// Kernel handles and the intentionally mutable client elements are excluded.
func (h *Helper) readPolicy(ctx context.Context) (string, error) {
	out, err := h.runner.Run(ctx, h.config.NFT, []string{"-j", "list", "table", "inet", "sreda"}, "")
	if err != nil {
		return "", err
	}
	var doc struct {
		NFTables []map[string]map[string]any `json:"nftables"`
	}
	if json.Unmarshal([]byte(out), &doc) != nil {
		return "", errors.New("invalid firewall state")
	}
	chains := map[string]bool{}
	rules := map[string]int{}
	tables, sets := 0, 0
	objects := []map[string]map[string]any{}
	for _, item := range doc.NFTables {
		if len(item) != 1 {
			return "", errors.New("invalid firewall object")
		}
		for kind, object := range item {
			if kind == "metainfo" {
				continue
			}
			if object["family"] != "inet" {
				return "", errors.New("invalid firewall family")
			}
			delete(object, "handle")
			switch kind {
			case "table":
				if object["name"] != "sreda" {
					return "", errors.New("invalid firewall table")
				}
				tables++
			case "set":
				if object["table"] != "sreda" || object["name"] != "clients" || object["type"] != "ipv4_addr" {
					return "", errors.New("invalid firewall set")
				}
				delete(object, "elem")
				sets++
			case "chain":
				name, _ := object["name"].(string)
				if (name != "input" && name != "forward" && name != "output") || chains[name] || object["table"] != "sreda" || object["type"] != "filter" || object["hook"] != name || object["prio"] != float64(-10) || object["policy"] != "accept" {
					return "", errors.New("invalid firewall chain")
				}
				chains[name] = true
			case "rule":
				name, _ := object["chain"].(string)
				if object["table"] != "sreda" || (name != "input" && name != "forward" && name != "output") {
					return "", errors.New("invalid firewall rule")
				}
				rules[name]++
			default:
				return "", errors.New("unexpected firewall object")
			}
			objects = append(objects, item)
		}
	}
	if tables != 1 || sets != 1 || len(chains) != 3 || rules["input"] != 2 || rules["forward"] != 2 || rules["output"] != 2 {
		return "", errors.New("firewall isolation incomplete")
	}
	encoded, err := json.Marshal(objects)
	return string(encoded), err
}
func (h *Helper) checkRoute(ctx context.Context, peer Peer) error {
	address := strings.TrimSuffix(peer.Address, "/32")
	out, err := h.runner.Run(ctx, h.config.IP, []string{"-4", "-j", "route", "get", address}, "")
	if err != nil {
		return err
	}
	var routes []struct {
		Device  string          `json:"dev"`
		Gateway string          `json:"gateway"`
		Type    string          `json:"type"`
		Via     json.RawMessage `json:"via"`
	}
	if json.Unmarshal([]byte(out), &routes) != nil || len(routes) != 1 || routes[0].Device != h.config.Interface || routes[0].Gateway != "" || len(routes[0].Via) != 0 || (routes[0].Type != "" && routes[0].Type != "unicast") {
		return errors.New("direct WireGuard route not confirmed")
	}
	return nil
}
func (h *Helper) remove(ctx context.Context, peer Peer) error {
	// Deny return packets first, including previously established connections.
	// A failed wg command still leaves the firewall denial in force.
	firewallErr := h.setClient(ctx, peer, false)
	_, removeErr := h.runner.Run(ctx, h.config.WG, []string{"set", h.config.Interface, "peer", peer.PublicKey, "remove"}, "")
	saved, verifyErr := h.peerAddress(ctx, peer.PublicKey)
	if firewallErr != nil || removeErr != nil || verifyErr != nil || saved != "" || h.checkPolicy(ctx) != nil {
		return errors.New("peer revocation not confirmed")
	}
	return nil
}
