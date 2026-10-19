package agentprotocol

import (
	"errors"
	"net"
	"strconv"
)

// ValidateTarget checks the literal local endpoint form; interface ownership is agent-side.
func ValidateTarget(target string) error {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return errors.New("укажите literal IP:порт приложения")
	}
	ip := net.ParseIP(host)
	number, err := strconv.Atoi(port)
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || err != nil || number < 1 || number > 65535 {
		return errors.New("недопустимый IP или порт приложения")
	}
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 10 && ip4[1] == 203 && ip4[2] == 0 {
		return errors.New("адреса WireGuard не являются локальным приложением")
	}
	return nil
}
