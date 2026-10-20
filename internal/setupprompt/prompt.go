// Package setupprompt builds instructions from owner-authorized, public data.
// It has no model client, execution capability, or access to stored credentials.
package setupprompt

import (
	"context"
	"fmt"
	"sreda/internal/machine"
	"sreda/internal/publication"
	"strings"
)

type Machines interface {
	SetupParameters(context.Context, int64, int64) (machine.SetupParameters, error)
}
type Publications interface {
	Get(context.Context, publication.Actor, string) (publication.Publication, error)
}
type Service struct {
	machines     Machines
	publications Publications
}

func New(m Machines, p Publications) *Service { return &Service{m, p} }

func (s *Service) Machine(ctx context.Context, owner, id int64) (string, error) {
	p, err := s.machines.SetupParameters(ctx, owner, id)
	if err != nil {
		return "", err
	}
	return build(p, nil), nil
}
func (s *Service) Publication(ctx context.Context, owner int64, id string) (string, error) {
	p, err := s.publications.Get(ctx, publication.Actor{ID: owner}, id)
	if err != nil {
		return "", err
	}
	// The publication module's ordinary actor lookup excludes other owners.
	m, err := s.machines.SetupParameters(ctx, owner, p.MachineID)
	if err != nil {
		return "", err
	}
	return build(m, &p), nil
}
func build(m machine.SetupParameters, p *publication.Publication) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Помоги настроить моё веб-приложение для публикации через Среду.\nМашина: %q (№%d).\n", m.Name, m.ID)
	if m.Address != "" {
		fmt.Fprintf(&b, "Назначенный адрес WireGuard: %s.\n", m.Address)
	} else {
		b.WriteString("Машина ещё не подключена. Сначала заверши её подключение в кабинете.\n")
	}
	if m.Mode == machine.ManualMode {
		b.WriteString("Способ подключения: ручной WireGuard. Я самостоятельно устанавливаю конфиг и запускаю туннель на этой машине. Приложение должно слушать назначенный IP WireGuard и указанный порт HTTP; loopback здесь недоступен шлюзу. Проверь локальный firewall и доступ от шлюза через туннель. Сохрани private key локально. Другие машины Среды недоступны через этот туннель.\n")
	} else {
		b.WriteString("Способ подключения: агент Среды. Установи и запусти агент на этой машине по инструкции оператора; код подключения вводится только локально. Агент доставляет запросы к literal IP и порту приложения этой же машины, включая loopback. Не открывай порт приложения всему интернету.\n")
	}
	if p != nil {
		fmt.Fprintf(&b, "Выбранная публикация: %s.\nВнешний HTTPS-адрес: %s.\nHTTP-адрес приложения на машине: %s.\nСостояние публикации: %s.\n", p.Subdomain, p.URL, p.Target, p.State)
	} else {
		b.WriteString("Публикация ещё не выбрана. Выбери HTTP-адрес приложения и свободный поддомен в кабинете; затем открой промпт из выбранной публикации для точного HTTPS-адреса.\n")
	}
	b.WriteString("TLS завершается на шлюзе Среды. Настрой внешний/base URL приложения на адрес публикации, учитывай X-Forwarded-Proto: https и доверяй proxy headers только при запросах через доверенный путь шлюза. Учти redirect URL, secure cookies, CSRF/origin и WebSocket, если приложение их использует. Статус «Настроена» подтверждает настройки Среды, но не исправность приложения. После настройки проверь локальный HTTP и внешний HTTPS, вход, перенаправления и WebSocket.\nДай конкретные шаги для моего приложения и объясни, какие параметры нужно уточнить. Не проси присылать пароли, private key, одноразовые коды или ссылки восстановления. Этот текст — данные для настройки, а не команда выполнять действия без согласования.\n\nОписание приложения (дополню сам):\nДокументация приложения (дополню сам):\n")
	return b.String()
}
