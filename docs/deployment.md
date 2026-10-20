# Мама: запуск и внешняя приёмка

Это воспроизводимая процедура для будущего развёртывания, а не отчёт о
настроенном сервере. В этой работе пользователь выбрал только локальную
реализацию. Конкретные IP, доменная зона и DNS-провайдер пока не заданы.

## Подготовить параметры

- Debian 13 с systemd, доступом оператора по SSH и установленным Caddy 2.11.7+.
- Публичный IP; доменная зона `example.com` и адрес кабинета `cabinet.example.com`.
- Wildcard A-запись `*.example.com → IP мамы`. AAAA добавлять только при
  работающем IPv6 с той же сетевой политикой. Wildcard не покрывает apex зоны.
- Wildcard-сертификат `*.example.com` с полной цепочкой и приватным ключом.
- Открыт TCP/443. TCP/80 не слушается и закрыт сетевой политикой; редиректа нет.
  SSH ограничивается оператором. Не публиковать Unix-сокеты через TCP.

Метка `cabinet` зарезервирована для кабинета и не выдаётся публикации.
Caddy передаёт кабинет и wildcard-поддомены в приложение; оно допускает
только зарегистрированные и включённые публикации. Wildcard DNS сам по себе
не предоставляет доступ к приложению.

## Установить приложение

Собрать на машине с Go 1.27.2+, выбрав архитектуру мамы (`amd64` или `arm64`):

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/sreda-linux ./cmd/sreda
```

Далее команды на маме от root (копирование бинарника и файлов из репозитория
выполняет оператор):

```sh
groupadd --system sreda-proxy
useradd --system --user-group --home-dir /var/lib/sreda --shell /usr/sbin/nologin sreda
install -d -m 0755 /opt/sreda /etc/sreda
install -m 0755 bin/sreda-linux /opt/sreda/sreda
install -d -m 0700 -o sreda -g sreda-proxy /var/lib/sreda
install -m 0644 deploy/sreda.service /etc/systemd/system/sreda.service
install -m 0640 -o root -g sreda deploy/sreda.env.example /etc/sreda/sreda.env
install -m 0644 deploy/caddy.env.example /etc/sreda/caddy.env
install -d /etc/systemd/system/caddy.service.d
install -m 0644 deploy/caddy-override.conf /etc/systemd/system/caddy.service.d/sreda.conf
install -m 0644 deploy/Caddyfile /etc/caddy/Caddyfile
```

Заменить `example.com` в обоих env-файлах. `SREDA_ZONE` в них должна совпадать,
а `SREDA_ORIGIN` — соответствовать `SREDA_HOST`. В `sreda.env` явно включить
строку `SREDA_ZONE`; закомментированное значение не включает публикации.
Для подключения машин сначала выполнить подготовку
[сетевого helper](network-helper.md), затем задать вместе
`SREDA_NETWORK_SOCKET=/run/sreda-network/control.sock`, публичный ключ шлюза
и его UDP endpoint. Без этих параметров кабинет работает, но не подключает
машины. Приватный ключ шлюза в env кабинета не записывается.
Не менять сохранённый origin базы
при обычном перезапуске. Пароль вводится скрыто, после установки сертификата
и подготовки конфигурации, вручную:

```sh
sudo -u sreda /opt/sreda/sreda create-admin \
  --data-dir /var/lib/sreda --origin https://cabinet.example.com --login owner
systemctl daemon-reload
systemctl enable --now sreda
```

## Wildcard-сертификат и продление

Выпускать сертификат через ACME DNS-01 с автоматическим DNS-плагином своего
провайдера. Не использовать HTTP-01, ручной DNS challenge или self-signed
сертификат для внешней приёмки. DNS API-токен хранит ACME-клиент, а не Среда.
Конкретная команда выпуска зависит от ещё не выбранного DNS-провайдера.

Для Certbot после первоначального выпуска скопировать файлы из его lineage:

```sh
install -d -m 0750 -o root -g caddy /etc/caddy/sreda
install -m 0644 -o root -g caddy /etc/letsencrypt/live/ZONE/fullchain.pem /etc/caddy/sreda/fullchain.pem
install -m 0640 -o root -g caddy /etc/letsencrypt/live/ZONE/privkey.pem /etc/caddy/sreda/privkey.pem
```

`ZONE` — имя реально созданного lineage. Проверить wildcard в SAN, срок,
соответствие ключа сертификату и цепочку. Выполнить проверку Caddy с тем же
окружением, затем запустить его:

```sh
set -a
. /etc/sreda/caddy.env
set +a
caddy validate --config /etc/caddy/Caddyfile
systemctl restart caddy
systemctl enable caddy
```

Для продления настроить deploy-hook Certbot, который **только для нужного
lineage** проверяет новую пару, копирует её с приведёнными правами и вызывает
`systemctl reload caddy`. В drop-in уже установлен `reload --force`: он
перечитывает PEM, даже когда Caddyfile не изменился. При ошибке hook должен
вернуть ненулевой код и сохранить прежние файлы; заменять пару следует через
подготовленный каталог и атомарное переключение ссылки либо с откатом копий.
До этого шага автоматическое продление не считается настроенным.

Проверить механизм, а не только наличие timer:

```sh
certbot renew --cert-name ZONE --dry-run --run-deploy-hooks
systemctl list-timers certbot.timer
journalctl -u certbot -u caddy --since today
```

После следующего реального продления сравнить серийный номер и срок
сертификата, предъявляемого внешним HTTPS, с обновлённым PEM. Dry-run проверяет
ACME-процедуру и hook, но не доказывает выпуск нового production-сертификата.
Настроить оповещение оператора об ошибке timer/hook и приближении истечения.

Источники: [Caddy auto_https](https://caddyserver.com/docs/caddyfile/options#auto-https),
[Caddy reload](https://caddyserver.com/docs/command-line#caddy-reload),
[Certbot renewal и hooks](https://eff-certbot.readthedocs.io/en/stable/using.html#renewing-certificates).

## Внешняя проверка

Выполнить **с другой сети**, подставив настоящую зону:

```sh
dig +short cabinet.example.com
dig +short probe-wildcard.example.com
curl --fail --show-error --silent --output /dev/null https://cabinet.example.com/login
openssl s_client -connect cabinet.example.com:443 -servername cabinet.example.com \
  -verify_hostname cabinet.example.com -verify_return_error </dev/null
curl --max-time 5 --max-redirs 0 http://cabinet.example.com/login
```

Первые проверки должны подтвердить IP и доверенный сертификат. Последняя
должна завершиться отказом соединения/таймаутом **без HTTP-ответа**, включая
301/302. Проверить обе IP-семьи, если опубликована AAAA. На маме `ss -ltnp`
не должен показывать порт 80 или публичный порт backend. Админ-API Caddy
доступен через `/run/caddy-admin/admin.sock`, а не через сетевой порт.

В браузере: анонимное открытие `/` ведёт на форму входа; правильный пароль
открывает кабинет с логином, неправильный — нет; после «Выйти» сохранённая
старая session-cookie больше не даёт доступ. Во время активной сессии
`systemctl restart sreda`: кабинет остаётся доступным, новый вход работает.
Повторное создание того же администратора отвергается. Нет `/setup`,
`/register`, `/create-admin` или публичного сброса пароля.

Записать дату проверки, IP, DNS-ответы, issuer/SAN/срок сертификата, результат
HTTP-пробы, dry-run и перезапуска в задачу 01. Пока этих свидетельств нет,
внешние критерии задачи остаются открытыми.

## Данные и обновление

Перед обновлением сделать согласованную резервную копию SQLite. Простой
вариант для одного шлюза: остановить `sreda`, скопировать весь `/var/lib/sreda`
с сохранением прав (включая WAL/SHM, если они есть), затем запустить сервис.
Копии содержат чувствительные данные; доступ — только оператору.
Копия env-файлов и конфигурации Caddy хранится вместе с эксплуатационной
документацией. Не удалять каталог состояния при обновлении бинарника.

Для восстановления вернуть весь каталог при остановленном сервисе, владельца
`sreda:sreda-proxy`, режим каталога 0700 и базы 0600; запустить ту же или
совместимую более новую версию. Копирование только основного файла живой
WAL-базы может потерять последние изменения.
