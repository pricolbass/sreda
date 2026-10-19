// sreda-network is the root-owned Linux boundary. It accepts only validated peer
// mutations over a restricted Unix socket, never commands or client paths.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sreda/internal/tunnel"
	"syscall"
	"time"
)

func run() error {
	flags := flag.NewFlagSet("sreda-network", flag.ContinueOnError)
	socket := flags.String("socket", "/run/sreda-network/control.sock", "absolute Unix socket")
	iface := flags.String("interface", "wg-sreda", "managed WireGuard interface")
	wg := flags.String("wg", "/usr/bin/wg", "root-owned wg executable")
	nft := flags.String("nft", "/usr/sbin/nft", "root-owned nft executable")
	ip := flags.String("ip", "/usr/sbin/ip", "root-owned ip executable")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || !filepath.IsAbs(*socket) {
		return errors.New("invalid helper arguments")
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("network helper requires Linux and root")
	}
	helper, err := tunnel.NewHelper(tunnel.HelperConfig{Interface: *iface, WG: *wg, NFT: *nft, IP: *ip}, tunnel.CommandRunner{})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if info, err := os.Lstat(*socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("socket path occupied")
		}
		conn, dialErr := net.DialTimeout("unix", *socket, time.Second)
		if dialErr == nil {
			conn.Close()
			return errors.New("helper already running")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return dialErr
		}
		if err := os.Remove(*socket); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.Listen("unix", *socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chmod(*socket, 0660); err != nil {
		return err
	}
	// Own the control socket before touching kernel state: a duplicate launch
	// must not clear the active helper's client set.
	initCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err = helper.Initialize(initCtx)
	cancel()
	if err != nil {
		return err
	}
	if address := os.Getenv("NOTIFY_SOCKET"); address != "" {
		conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: address, Net: "unixgram"})
		if err != nil {
			return errors.New("service readiness not confirmed")
		}
		_, err = conn.Write([]byte("READY=1"))
		conn.Close()
		if err != nil {
			return errors.New("service readiness not confirmed")
		}
	}
	server := &http.Server{Handler: helper, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 4096}
	go func() { <-ctx.Done(); server.Close() }()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
