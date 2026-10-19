package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/term"
	"io"
	"os"
	"os/signal"
	"sreda/internal/agent"
	"strings"
	"syscall"
)

func run() error {
	if len(os.Args) < 2 || (os.Args[1] != "enroll" && os.Args[1] != "run") {
		return errors.New("использование: sreda-agent <enroll|run> [--state-dir DIR] [--origin https://HOST]")
	}
	flags := flag.NewFlagSet(os.Args[1], flag.ContinueOnError)
	dir := flags.String("state-dir", "/var/lib/sreda-agent", "закрытый каталог состояния")
	origin := flags.String("origin", "", "HTTPS-адрес кабинета")
	codeStdin := flags.Bool("code-stdin", false, "прочитать код из stdin (автоматизация)")
	if err := flags.Parse(os.Args[2:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("неизвестные аргументы")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if os.Args[1] == "run" {
		return agent.Run(ctx, *dir, os.Stdout)
	}
	var code string
	if *codeStdin {
		scanner := bufio.NewScanner(io.LimitReader(os.Stdin, 1024))
		if !scanner.Scan() {
			return errors.New("не удалось прочитать код")
		}
		code = scanner.Text()
	} else {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return errors.New("нужен терминал; для автоматизации явно укажите --code-stdin")
		}
		fmt.Fprint(os.Stderr, "Код подключения: ")
		raw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		code = string(raw)
	}
	if _, err := agent.Enroll(ctx, *dir, *origin, strings.TrimSpace(code), nil); err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "Агент зарегистрирован. Запустите службу sreda-agent; состояние связи появится после запуска WireGuard.")
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
