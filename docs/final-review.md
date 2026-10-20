# Итоговое ревью первой версии

20 октября 2026 года. Две независимые проверки по навыку
`mattpocock-skills:code-review`. Ниже сохранены отдельные отчёты каждой оси.

Исходная точка: `76fa2af` (`main`). Проверенная реализация: `72c23f2`.
Первые исправления выполнены одним implementer в `58a8fe4`, независимо
объединены в `8436199`. Дополнительное замечание по бюджету восстановления
выявлено отдельным воспроизведением после первого раунда и исправлено тем же
implementer в `846a1b1`. Внешние условия приёмки остаются за пределами
локального выполнения.

## Standards

Standards review: `76fa2af...72c23f2` (final tip verified).

**Documented breach — application decisions have returned to SQLite adapters.** `docs/implementation.md:32–33` says “Прикладные операции принимают решение по зафиксированному снимку; адаптер применяет его атомарно”; `docs/machine-module.md:5–7` likewise places policy outside storage. Yet `internal/machine/access_sqlite.go:25–56` decides actor permissions (`OwnerID != c.actor.ID && (!c.actor.Admin || enabled)`) and eligibility; `internal/machine/reconnection_sqlite.go:20–58` decides ownership and whether replacement is fresh or resumable. `internal/identity/access_sqlite.go:33–51,94–114` similarly decides administrator authorization and block/unblock transitions (`if state != "Доступ закрыт" { return AccessIncomplete }`), while the Manager methods merely delegate. Changing these product rules requires changing persistence code, contrary to the documented separation. Move decisions into the application operations, evaluated through operation-specific snapshot callbacks inside the existing transaction, as publication access/deletion already do. Keep SQL revision, lease, credential, and owner-version guards in the adapters: those enforce atomicity and are not the breach. No repository interface or generic CRUD layer is needed.

**Possible Duplicated Code — publication closure coordination.** `internal/publication/access.go:62–78`, `deletion.go:43–58`, `blocking.go:17–50`, `reconnection.go:19–37`, and `recovery.go:31–46` repeat the lifecycle shape: “`route.stopAdmission()`”, unlock, bounded “`route.closeAndWait(closeCtx)`”, lock, identity-check the cached route, then delete it. The copies already differ: blocking initiates cancellation for every route before waiting (`blocking.go:25–29`), whereas reconnection closes sequentially. A closure synchronization change must be propagated across five operations. Extract the concrete private route capture/stop, bounded drain, and identity-safe removal shape; retain each operation’s distinct persistence outcome and cancellation budget in its caller. This is a heuristic maintainability finding, not a claim that the differing workflows should become one framework.

Total: one documented boundary breach (three affected storage areas), one possible smell. Compatibility delegates and private concrete SQLite stores are explicitly allowed by repository documentation and were not flagged. No broad tests were run in this read-only review.

### Проверка исправлений

Verified `72c23f2..58a8fe41392c0d1de7dc1dc8ad91fb0a2d544b23` read-only.

Both original findings are resolved.

- **Documented boundary breach:** identity block/unblock authorization and transition decisions now reside in `internal/identity/access.go`; machine access and reconnection decisions reside in `internal/machine/access.go` and `reconnection.go`. The existing SQLite transactions read snapshots, invoke these operation-specific callbacks, and atomically persist decisions. Revision, lease, credential, and owner-version enforcement remains in storage. This matches `docs/implementation.md:32–33` without introducing a generic repository layer.
- **Possible duplication smell:** `internal/publication/closure.go` owns concrete route capture/stop, bounded drain, and identity-safe eviction helpers, reused by access, deletion, blocking, reconnection, and recovery. Workflow-specific persistence and budgets remain in their callers. Bulk cancellation now starts before waits in both blocking and reconnection.

No introduced Standards issue found in the reviewed changes, including the accompanying manual-confirmation recovery and stale-intent fencing. No full suite or other tests were run during this verification; test evidence remains with the parent review.

## Spec

Spec review: 76fa2af165f27049d34a2a8a2d6039f73669610c...72c23f2; authorized local scope. First three findings fixed and re-reviewed at58a8fe4; fourth pending.

(a) Missing/partial requirements: recovery gaps below.

(b) Unasked behavior:

[P2] Owner-only individual machine disable.
internal/machine/access_sqlite.go:27; cabinet/machine_http.go:103.
Spec:31: «Администратор видит ресурсы всех пользователей, их владельцев, настройки и состояние; может отключить любую публикацию. Эти права не означают доступ к содержимому приложений или произвольное редактирование чужих ресурсов.»
UI/server also permit disabling foreign machines, changing owner intent outside publication-disable/user-block actions. Remove that grant. HTTP+SQLite overlay confirmed button, POST303 and disabled connection.

(c) Incorrect behavior:

[P2] Recover manual publication confirmation.
agentcontrol/controller.go:34–40/:85–95; cabinet/machines.go:56–63.
Issue10:11: «После перезапуска серверной части, Caddy и сетевых компонентов нужное состояние восстанавливается из сохранённых данных. Определены порядок восстановления и обращение с незавершёнными изменениями.»
Manual reconnection puts publications into «Настраивается». Enrollment commits peer/consumed code before ConfirmManual; interruption leaves configuring forever. Recovery never confirms; retry only reads parameters; admission.go:35 returns503. Persist/reconcile confirmation. Diagnostic injected-failure overlay reproduced reopen/reconcile failure; permanent regression uses HTTP/SQLite trigger.

[P2] Fence stale OFF recovery.
machine/manager.go:225–238; machine/access_sqlite.go:34/:71.
Issue10:11 applies; spec:168: «При потере связи и возвращении машины включённые публикации сохраняют адреса и автоматически восстанавливают доступ.»
OFF snapshots bypass desired-state recheck and overwrite newer owner enable. Validate current intent/both epochs. Two-App HTTP/SQLite overlay: pause first Apply, enable second, heartbeat200; resume, heartbeat401 and Enable returns.

[P2] Prevent closure retries starving healthy recovery.
command/serve.go:82; cabinet/machines.go:56–64; access/controller.go:44–46; machine/blocking.go:26–27.
Issue10:11 applies; issue10:16: «Испытания охватывают оба способа подключения и подтверждают, что восстановление одного пользователя не изменяет состояние ресурсов другого.»
Sequential coordinator gives all work20s, but initial user closure independently spends30s on10s revocations. Three slow blocked-owner peers exhaust each pass before healthy recovery; failed closure remains first nextpass. After helper restart clears allowed clients, healthy owners never recover until unrelated failure resolves. Preserve fail-closed cleanup with fair/independent phase opportunities. Scaled HTTP/SQLite overlay: repeated15ms passes spend40ms closing, healthy Apply never runs;1s control restores it. Production20s/30s source budgets establish starvation; arbitrary caller cancellation should still stop work.

External Linux/LXC, public TLS and100-LXC gates remain separate. No repository edits/fullsuite rerun; diagnostic overlays/evidence in /private/tmp.

### Проверка первых трёх исправлений

Spec verification of 72c23f2..58a8fe41392c0d1de7dc1dc8ad91fb0a2d544b23: all three P2 findings resolved.

- Manual confirmation recovery: reconciliation now runs after peer recovery, selects persisted configuring publications and confirms only current enabled/manual connections with matching owner/connection epochs and no unfinished enrollment, access, deletion or replacement operation. Disabled/deleting publications stay excluded. The regression uses real HTTP and SQLite failure triggers for both enrollment paths, reopens/reconciles repeatedly and verifies actual application delivery.
- Administrative scope: machine access policy and disable UI now require the owner. The HTTP regression preserves administrator inspection, rejects foreign disable, confirms the owner's connection remains live and verifies owner disable still works.
- Stale OFF recovery: snapshots carry both machine and owner revisions. Transactional policy rechecks those revisions, current effective intent and pending replacement/deletion for both restoration directions. The two-App regression pauses the external gateway, commits newer owner enable and verifies recovery preserves heartbeat and enabled intent.

No introduced Spec issue found in the reviewed diff. Examined new regressions and reported targeted race/vet evidence; no additional full suite run. External Linux/LXC, public TLS and capacity gates remain unchanged.

### Дополнительное замечание: бюджет восстановления

Подтверждено через HTTP и настоящую SQLite: два последовательных коротких
прохода тратят весь бюджет на незавершённую блокировку, а восстановление
здорового подключения другого владельца не начинается. Контрольный проход
с достаточным временем восстанавливает его. Производственные пределы —
20 секунд на весь проход и независимые 30 секунд на очистку peers —
позволяют тому же сбою повторяться после перезапуска helper.
Исправлено в `846a1b1`: сервер передаёт контекст своей жизни, а последовательные
этапы согласования получают отдельные бюджеты по 20 секунд. Явная отмена
вызывающего контекста сохраняется. Независимая ограниченная защитная очистка,
leases и транзакционные проверки версий не менялись. Начальное восстановление
до приёма HTTP теперь может занять сумму бюджетов этапов и безопасной очистки.

Регрессия `TestServerRecoveryRestoresHealthyOwnerAfterSlowUnfinishedBlock`
запускает настоящий серверный CLI с SQLite и Unix helper. Три ошибки отзыва
по 7 секунд превышают прежний производственный лимит. На `8436199` тест
воспроизвёл сбой за 22.15 s; после исправления прошёл за 22.14 s.
Проверены применение здорового peer до приёма HTTP, его heartbeat 200,
отказ заблокированному агенту 401 и запрет преждевременной разблокировки 409.

## Свидетельства исправлений

Существующие тесты первого раунда не менялись. Добавлены три регрессии
через HTTP и настоящую SQLite: ошибка подтверждения ручной публикации
после commit подключения; запрещённое администратору изменение чужой машины;
устаревший фоновый проход после нового включения владельцем.
Внешняя граница сети управляется тестовым адаптером, ошибка SQLite —
настоящим trigger. Внутренние модули в этих регрессиях не имитируются.

Целевой race-набор жизненного цикла: PASS, 287.657 s.
Дополнительный race-набор новых регрессий и восстановления: PASS, 31.309 s.
Полный race-набор после первого раунда (`8436199`): PASS для всех пакетов,
`internal/cabinet` — 554.410 s. Подробности и ограничения записаны в
[отчёте приёмки](local-acceptance.md).

После дополнительного исправления `846a1b1` целевой race-набор прошёл:
15 тестов кабинета — 171.930 s; три теста команд/процессов — 8.641 s.
Новая регрессия производственного запуска — PASS, 36.43 s. Повторно прошли
`make check` и сборки всех трёх программ для Linux amd64/arm64 без CGO.
Полный набор после этого малого изменения не повторялся. Упоминание
ожидающего race-прогона в исходном подтверждении рецензента ниже относится
к моменту его проверки кода; итог этого прогона теперь записан здесь.


### Spec: committed budget repair verification

Read-only verification of committed repair8436199..846a1b1e5324b65646c69a05f0e69639a3ccf56f in /Users/nya/Desktop/sreda/final-review-fixes: fourth Spec P2 resolved. HEAD matches that exact commit and the worktree is clean; production changes and regression match the previously inspected repair.

Production now passes the server lifetime context into reconciliation. The ordered access, publication, machine and manual-confirmation phases each derive a fresh20s budget from that context. An unfinished owner's independently bounded cleanup can therefore overrun its access-phase budget without expiring the later healthy-owner recovery budget. Explicit caller deadlines/cancellation still propagate; safety cleanup and closure leases are unchanged.

The added regression exercises the actual CLI process, HTTP, SQLite and Unix helper with three7s revocation failures, exceeding the former20s pass budget. It asserts the independent healthy peer is applied before startup completes, its heartbeat succeeds, the blocked peer remains rejected and unblocking remains forbidden while closure is unconfirmed. This directly covers the reported production scheduling gap rather than requiring arbitrary caller cancellation to be ignored.

No introduced Spec issue found in the inspected diff. Reported red22.15s/green22.14s process evidence supports the source analysis; no additional suite run. Committed source verified; targeted race completion remains pending. No wait or retest performed.

### Standards: budget repair verification

Standards follow-up: verified committed diff `8436199c993bcab59188b6951b455fc282c02fa8..846a1b1e5324b65646c69a05f0e69639a3ccf56f` in `/Users/nya/Desktop/sreda/final-review-fixes`, including `internal/cabinet/coordinator_recovery_test.go`. The working tree is clean. Production and test changes match the previously inspected repair; documentation only received line reflow.

No new documented-standard breach or actionable baseline smell found.

`internal/command/serve.go` supplies the server lifetime context; `internal/cabinet/machines.go` owns ordered cross-module coordination and creates separate bounded contexts for access closure, publication closure, machine recovery, and manual confirmation. The arrangement respects the documented composition boundary and leaves persisted state decisions and network cleanup in their existing modules. Each phase inherits caller cancellation; independent bounded compensation remains unchanged.

The explicit four-phase sequence is small and cohesive; a generic executor or workflow framework is unnecessary. The test helper's optional startup timeout has a concrete caller, and its bounded request context prevents startup probing from hanging. The new process test exercises the production coordinator through its existing external network boundary and checks both healthy-owner recovery and continued blocking. Updated recovery documentation accurately distinguishes per-phase budgets from total startup duration.

No tests were run. The original two Standards findings remain resolved.

Standards: 2 исходных замечания, исправлены оба; новых не выявлено. Spec: 4 P2,
исправлены все. Открытых замечаний по обеим осям — 0. Внешние проверки
не считаются пройденными.
