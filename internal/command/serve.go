package command

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"sreda/internal/cabinet"
	"sreda/internal/tunnel"
)

func serve(dir, origin, socket string, output io.Writer) error {
	if !filepath.IsAbs(socket) {
		return errors.New("--socket: нужен абсолютный путь к Unix-сокету")
	}
	app, err := cabinet.Open(dir, origin)
	if err != nil {
		return err
	}
	defer app.Close()
	if zone := os.Getenv("SREDA_ZONE"); zone != "" {
		if err := app.ConfigurePublicationZone(zone); err != nil {
			return err
		}
	}
	networkSocket, publicKey, endpoint := os.Getenv("SREDA_NETWORK_SOCKET"), os.Getenv("SREDA_WG_PUBLIC_KEY"), os.Getenv("SREDA_WG_ENDPOINT")
	hasNetwork := networkSocket != "" || publicKey != "" || endpoint != ""
	if hasNetwork {
		if !filepath.IsAbs(networkSocket) || publicKey == "" || endpoint == "" {
			return errors.New("задайте SREDA_NETWORK_SOCKET (абсолютный путь), SREDA_WG_PUBLIC_KEY и SREDA_WG_ENDPOINT вместе")
		}
		details := tunnel.Details{GatewayPublicKey: publicKey, Endpoint: endpoint, GatewayAddress: "10.203.0.1/32"}
		if err := details.Validate(); err != nil {
			return err
		}
		app.SetGateway(tunnel.NewClient(networkSocket, details))
	}
	if info, err := os.Lstat(socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("путь сокета занят обычным файлом")
		}
		connection, dialErr := net.DialTimeout("unix", socket, time.Second)
		if dialErr == nil {
			connection.Close()
			return errors.New("сервер уже запущен")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return dialErr
		}
		if err := os.Remove(socket); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chmod(socket, 0660); err != nil {
		return err
	}
	server := &http.Server{
		Handler: app.Handler(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	reconcileDone := make(chan struct{})
	defer func() { stop(); <-reconcileDone }()
	reconcile := func() {
		operationCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		if err := app.ReconcileMachinePeers(operationCtx); err != nil && ctx.Err() == nil {
			fmt.Fprintln(output, "Восстановление сохранённых изменений не подтверждено; повтор через 30 секунд.")
		}
	}
	// The listener has been claimed, but published HTTP traffic is accepted only
	// after the first bounded restoration attempt. Failed work stays persisted.
	reconcile()
	go func() {
		defer close(reconcileDone)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				reconcile()
			}
		}
	}()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			server.Close()
		}
	}()
	fmt.Fprintln(output, "Кабинет слушает Unix-сокет:", socket)
	err = server.Serve(listener)
	stop()
	<-finished
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
