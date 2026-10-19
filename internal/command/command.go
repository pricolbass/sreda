package command

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
	"sreda/internal/cabinet"
)

func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 || (args[0] != "create-admin" && args[0] != "reset-admin" && args[0] != "serve") {
		return errors.New("использование: sreda <create-admin|reset-admin|serve> --data-dir DIR [--origin https://HOST]")
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("data-dir", os.Getenv("SREDA_DATA_DIR"), "каталог данных")
	origin := flags.String("origin", os.Getenv("SREDA_ORIGIN"), "HTTPS-адрес кабинета (нужен при первом запуске)")
	login := flags.String("login", "", "логин администратора")
	fromStdin := flags.Bool("password-stdin", false, "прочитать одну строку пароля из stdin (для автоматизации)")
	socket := flags.String("socket", os.Getenv("SREDA_SOCKET"), "абсолютный путь к Unix-сокету (serve)")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("неизвестные аргументы")
	}
	if args[0] == "serve" {
		return serve(*dir, *origin, *socket, stderr)
	}
	var password string
	if *fromStdin {
		scanner := bufio.NewScanner(io.LimitReader(stdin, 1024))
		if !scanner.Scan() {
			return errors.New("не удалось прочитать пароль")
		}
		password = scanner.Text()
	} else {
		file, ok := stdin.(*os.File)
		if !ok || !term.IsTerminal(int(file.Fd())) {
			return errors.New("нужен терминал; для автоматизации явно укажите --password-stdin")
		}
		fmt.Fprint(stderr, "Пароль: ")
		first, err := term.ReadPassword(int(file.Fd()))
		fmt.Fprintln(stderr)
		if err != nil {
			return err
		}
		fmt.Fprint(stderr, "Повторите пароль: ")
		second, err := term.ReadPassword(int(file.Fd()))
		fmt.Fprintln(stderr)
		if err != nil {
			return err
		}
		if string(first) != string(second) {
			return errors.New("пароли не совпадают")
		}
		password = string(first)
	}
	app, err := cabinet.Open(*dir, *origin)
	if err != nil {
		return err
	}
	defer app.Close()
	if args[0] == "reset-admin" {
		if err := app.ResetAdministratorPassword(strings.TrimSpace(*login), password); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "Пароль администратора изменён. Прежние сессии отозваны.")
		return nil
	}
	if err := app.CreateAdministrator(strings.TrimSpace(*login), password); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "Администратор создан.")
	return nil
}
