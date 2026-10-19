package agent

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sreda/internal/agentprotocol"
	"strings"
	"time"
)

func validateControl(c agentprotocol.Control) error {
	client, err := netip.ParsePrefix(c.Address)
	if err != nil || !client.Addr().Is4() || client.Bits() != 32 || !netip.MustParsePrefix("10.203.0.0/24").Contains(client.Addr()) || client.Addr() == netip.MustParseAddr("10.203.0.1") {
		return errors.New("кабинет вернул недопустимый адрес машины")
	}
	gateway, err := netip.ParsePrefix(c.Tunnel.GatewayAddress)
	if err != nil || gateway.String() != "10.203.0.1/32" {
		return errors.New("неподдерживаемый адрес шлюза")
	}
	key, err := base64.StdEncoding.DecodeString(c.Tunnel.GatewayPublicKey)
	if err != nil || len(key) != 32 || len(c.Tunnel.GatewayPublicKey) != 44 {
		return errors.New("некорректный ключ шлюза")
	}
	if host, port, err := net.SplitHostPort(c.Tunnel.Endpoint); err != nil || host == "" || port == "" || strings.ContainsAny(c.Tunnel.Endpoint, "\r\n\t ") {
		return errors.New("некорректный endpoint шлюза")
	}
	if len(c.ProxyToken) != 43 || c.MachineID < 1 {
		return errors.New("некорректная конфигурация подключения")
	}
	return nil
}
func wireGuardConfig(s State) (string, error) {
	if err := validateControl(s.Control); err != nil {
		return "", err
	}
	key, err := base64.StdEncoding.DecodeString(s.PrivateKey)
	if err != nil || len(key) != 32 || len(s.PrivateKey) != 44 {
		return "", errors.New("повреждён приватный ключ")
	}
	return fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\n\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s\nPersistentKeepalive = 25\n", s.PrivateKey, s.Control.Address, s.Control.Tunnel.GatewayPublicKey, s.Control.Tunnel.Endpoint, s.Control.Tunnel.GatewayAddress), nil
}

// Run requires Linux root and wg-quick; the install unit supplies these prerequisites.
// It binds no public listener and does not advertise readiness before the tunnel is applied.
func Run(ctx context.Context, dir string, output io.Writer) error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("служба агента поддерживает Debian LXC и запускается от root")
	}
	state, err := LoadState(dir)
	if err != nil {
		return err
	}
	if state.PendingCode != "" {
		return errors.New("подключение не завершено; повторите enroll с тем же кодом")
	}
	config, err := wireGuardConfig(state)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "wg-sreda.conf")
	if err = os.WriteFile(path, []byte(config), 0600); err != nil {
		return err
	}
	if err = os.Chmod(path, 0600); err != nil {
		return err
	}
	binary, err := exec.LookPath("wg-quick")
	if err != nil {
		return errors.New("установите wireguard-tools")
	}
	// Own interface only. A previous service termination may have left it active.
	if _, err := net.InterfaceByName("wg-sreda"); err == nil {
		if err := exec.CommandContext(ctx, binary, "down", path).Run(); err != nil {
			return errors.New("не удалось убрать предыдущее подключение wg-sreda")
		}
	}
	if err = exec.CommandContext(ctx, binary, "up", path).Run(); err != nil {
		return errors.New("WireGuard не применён; проверьте права LXC и инструкцию установки")
	}
	defer exec.Command(binary, "down", path).Run()
	clientAddr := netip.MustParsePrefix(state.Control.Address).Addr().String()
	gatewayAddr := netip.MustParsePrefix(state.Control.Tunnel.GatewayAddress).Addr().String()
	listener, err := net.Listen("tcp", net.JoinHostPort(clientAddr, "9080"))
	if err != nil {
		return errors.New("не удалось открыть listener агента на адресе WireGuard")
	}
	defer listener.Close()
	proxy := NewProxy(gatewayAddr)
	defer proxy.Close()
	if err = proxy.ApplyControl(state.Control); err != nil {
		return err
	}
	server := &http.Server{Handler: proxy, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10}
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	defer server.Close()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	client := defaultClient(nil)
	lastSuccess := time.Now()
	fmt.Fprintln(output, "Агент запущен; публикации управляются из кабинета.")
	for {
		requestCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		control, controlErr := heartbeat(requestCtx, client, state, true)
		cancel()
		if controlErr == nil {
			if err = validateControl(control); err != nil {
				return err
			}
			if control.Address != state.Control.Address || control.Tunnel != state.Control.Tunnel {
				return errors.New("конфигурация туннеля изменилась; перезапустите агент")
			}
			if err = proxy.ApplyControl(control); err != nil {
				return err
			}
			state.Control = control
			if err = saveState(dir, state); err != nil {
				return err
			}
			lastSuccess = time.Now()
		} else {
			var protocolErr *ProtocolError
			if errors.As(controlErr, &protocolErr) && (protocolErr.Status == 401 || protocolErr.Status == 403) {
				return errors.New("подключение отозвано или отключено в кабинете")
			}
			fmt.Fprintln(output, "Нет управляющей связи с кабинетом; повтор через 30 секунд.")
			if time.Since(lastSuccess) > 90*time.Second {
				proxy.Close()
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case err := <-served:
			return err
		case <-ticker.C:
		}
	}
}
