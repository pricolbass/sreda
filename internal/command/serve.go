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
		ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
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
