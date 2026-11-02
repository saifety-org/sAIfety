# sAIfety

Локальный шлюз безопасности для AI-агентов: проверка репозиториев, MCP-прокси
и хуки Claude Code. sAIfety ищет prompt injection в инструкциях и ответах
инструментов, предупреждает об опасных командах и маскирует секреты и
персональные данные перед передачей агенту.

Анализ работает локально. По умолчанию используется встроенная модель, которой
не нужны сеть, внешний API или отдельное скачивание весов.

## Что делает приложение

- **Проверяет содержимое.** Обнаруживает попытки перехватить инструкции агента,
  поддельные системные сообщения, скрытый текст и опасные настройки агента.
  Нормализует Unicode и омоглифы, декодирует вложенные кодировки, разбирает
  shell-команды парсером с анализом потоков данных. Сводный проход ищет
  инструкции и сигналы, распределённые по файлам.
- **Фильтрует MCP.** Объединяет настроенные серверы за одним прокси, проверяет
  описания инструментов и их результаты, предупреждает об изменении определений
  инструментов (rug-pull), коллизиях имён и попытках подменить другие инструменты.
  Поддерживает stdio, HTTP, SSE и WebSocket на стороне серверов.
- **Маскирует данные.** Удаляет ключи, токены и другие секреты, русские
  ФИО и мобильные РФ (`+79…`, `79…`, `89…`, включая скобки и тире).
  По умолчанию ПДн распознаются локальными правилами без модели;
  дополнительный NER включается явно.
- **Подключается к Claude Code.** Хуки проверяют инструкции при старте,
  ограничивают доступ к заблокированным источникам и очищают вывод инструментов.
  Команда `launch` сканирует проект и запускает Claude с прокси и этими хуками.
- **Выдаёт отчёты.** CLI формирует текст, JSON или SARIF для ручной проверки
  и CI. Есть счётчики находок отдельно для сканирования, прокси и хуков.
  В изображениях проверяется текст метаданных и SVG; OCR включается отдельно.

Анализируемые команды не выполняются. `scan` только выдаёт отчёт и код возврата,
не переписывая файлы. В прокси и хуках политика определяет действие:
предупреждение, очистка содержимого или блокировка источника.

Распознанные значения скрываются полностью, включая инициалы и все цифры
телефона. В MCP учитываются строки, числа и явные поля ПДн; ошибки upstream
не раскрывают исходные детали. Бинарные ответы по умолчанию удерживаются,
поскольку проверить их на ПДн нельзя. Подробнее о совместимости и явных
исключениях — в [описании маскирования](docs/configuration.md#проверка-mcp-ответов).

## Сборка и установка

Нужен Go 1.26+. Для обычного использования достаточно сборки без нативных
зависимостей:

```sh
git clone https://github.com/saifety-org/sAIfety.git
cd sAIfety
make build-lite
./bin/saifety scan -fail-on critical /path/to/project
```

Для установки в `$(go env GOPATH)/bin` используйте `make install-lite` и добавьте
этот каталог в `PATH`. Альтернатива — `PREFIX=$HOME/.local make install-bin-lite`
с добавлением `~/.local/bin` в `PATH`.

`make build` собирает тот же инструмент с поддержкой ONNX и требует
C-компилятор. **Обе сборки по умолчанию используют встроенный классификатор
`trained`.** ONNX-модели нужны только при выборе соответствующего режима.
Готовые бинарники и `scripts/install.sh` требуют опубликованного
[релиза](https://github.com/saifety-org/sAIfety/releases).

## Как использовать

### Проверка репозитория и CI

```sh
saifety scan /path/to/project
saifety scan -format json /path/to/project
saifety scan -format sarif -fail-on critical /path/to/project
saifety scan -ocr /path/to/project  # нужен tesseract в PATH
```

Коды возврата: `0` — нет находок, достигающих выбранного порога, `1` — base,
`2` — medium, `3` — critical, `64` — ошибка аргументов, `70` — сбой.
По умолчанию порог — `base`; `-fail-on` меняет только условие ненулевого
кода, все находки остаются в отчёте.

### Защита MCP-клиента

```sh
saifety install claude-code -dry-run
saifety install claude-code
saifety uninstall claude-code  # восстановить конфигурацию из резервной копии
```

`install` переносит настройки MCP-серверов клиента в пользовательский конфиг
sAIfety и подключает вместо них прокси. Поддерживаются `claude-code`,
`claude-desktop`, `cursor`, `windsurf`, `vscode` и `all`. После установки
перезапустите клиент. Для ручного подключения настройте `mcpServers` в
`saifety.json` и укажите `saifety proxy` как stdio-сервер клиента.

Отказ proxy сообщает статус карантина без инструкции агенту отправлять сообщения
или запрашивать разблокировку через инструменты. Разблокировка остаётся действием
оператора вне MCP-инструментов. Область существующего карантина — сервер/инструмент;
блокировка одного ответа может затронуть последующие документы того же инструмента.

Для диагностики можно явно задать `saifety proxy -decision-log /path/to/new.jsonl`.
Создаётся новый приватный файл без перезаписи. Он содержит хеш ID вызова, факт
обращения upstream, решение, доставку (`original`, `transformed`, `withheld`),
причину и до 128 находок: detector/category/level/confidence; общее число находок
сохраняется отдельно. Аргументы, task, исходный текст, source и excerpts не пишутся.
Журнал не передаётся агенту и не предоставляет способ обхода карантина.
Ошибка записи диагностируется в stderr и не меняет защитное решение; неполный
журнал нельзя считать полным доказательством решений. Без флага журнал выключен.

### Проверка и запуск Claude Code

```sh
saifety launch /path/to/project
saifety launch /path/to/project -- --model opus
saifety launch -dry-run /path/to/project
```

При критичных находках `launch` отменяет запуск; `-force` позволяет явно
переопределить это решение. Настройки прокси и хуков создаются во временном
профиле. Для ручного подключения хуков есть `saifety hook
<session-start|pre-tool-use|post-tool-use>`.

## Настройки и модели

Конфигурация читается из пользовательского каталога ОС, а не из проверяемого
проекта. Путь можно задать через `SAIFETY_CONFIG` или `-config`.
См. [пример конфига](configs/saifety.example.json) и
[подробную конфигурацию](docs/configuration.md).

- `trained` — встроенная логистическая регрессия на символьных n-граммах;
  режим по умолчанию, без скачивания.
- `lexical` — классификация по правилам и языковым шаблонам.
- `onnx` — английская DeBERTa для prompt injection; нужна сборка `make build`.
  При первом использовании скачивает модель в локальный кэш. Если она
  недоступна, приложение сообщает об откате к `lexical`.
- `auto` — использует уже скачанную ONNX-модель, иначе `lexical`.

`saifety model pull` скачивает только DeBERTa для классификации инъекций;
`saifety model status` показывает состояние кэша. ПДн распознаются одинаковыми
правилами в `scan`, прокси и хуках. NER выключен по умолчанию.
Для него есть отдельная команда `saifety model pull-pii` и явная настройка
`"redact": {"ner": true}`; одного наличия файлов в кэше недостаточно.
`-deep` сохранён для совместимости и больше не меняет обработку ПДн.
По умолчанию действует политика `strict`; менее чувствительный профиль — `balanced`.

Собственная модель поставляется из отдельного Go-модуля
[prompt-injection-model](https://github.com/saifety-org/prompt-injection-model).
Его версия закреплена в `go.mod`, веса включаются в бинарник при сборке.
Обновление модели выполняется отдельным PR зависимости приложения.
`saifety version` показывает версии приложения и модели, SHA256 весов и схему
признаков. Релизные бинарники сопровождаются `VERSION.txt` с этими данными
и `SHA256SUMS` для проверки файлов.

## Границы защиты

sAIfety анализирует переданное ему содержимое и трафик подключённых MCP-серверов.
Он не является песочницей и не контролирует каналы, которые обходят прокси и хуки.
Детекторы и модели могут пропускать угрозы и выдавать ложные срабатывания;
маскирование также не гарантирует обнаружение всех секретов и ПДн.
Разовый `scan` не фильтрует дальнейшую сессию агента.

## Статус и планы

Состояние на ноябрь 2026 года. Таблица отражает смёрженное в `main`, открытые
PR и ветки, а также известные планы; это не обещание сроков.

| Возможность / задача | Статус | Комментарий / ссылка |
|---|---|---|
| **MCP-прокси** | | |
| Объединение серверов, `tools/list` и `tools/call` (stdio, HTTP, SSE, WebSocket) | ✅ | Базовая функциональность |
| Проверка structured-результатов и embedded resources | ✅ | [#7](https://github.com/saifety-org/sAIfety/pull/7) |
| Детекция rug-pull, коллизий и подмены инструментов | ✅ | [Целостность MCP-инструментов](docs/configuration.md#целостность-mcp-инструментов) |
| Синхронизация blocklist между горутинами и процессами | ✅ | [#8](https://github.com/saifety-org/sAIfety/pull/8) |
| Нейтральные отказы и приватный журнал решений (`-decision-log`) | ✅ | [#10](https://github.com/saifety-org/sAIfety/pull/10) |
| Кэш вердиктов описаний с учётом флага `trusted` | 🚧 | [#30](https://github.com/saifety-org/sAIfety/pull/30), задача [#26](https://github.com/saifety-org/sAIfety/issues/26) |
| Агрегация `resources/*` и `prompts/*` | ⬜ | Отмечено как «later step» в `internal/mcp/proxy.go` |
| Безопасная область карантина MCP-результатов | ⬜ | [#13](https://github.com/saifety-org/sAIfety/issues/13) |
| Доверенный контекст задачи и разрешений в MCP и хуках | ⬜ | [#14](https://github.com/saifety-org/sAIfety/issues/14) |
| **Детекция инъекций** | | |
| Встроенный классификатор `trained` из модуля [prompt-injection-model](https://github.com/saifety-org/prompt-injection-model) | ✅ | [#1](https://github.com/saifety-org/sAIfety/pull/1), [#3](https://github.com/saifety-org/sAIfety/pull/3) |
| Режимы `lexical`, `onnx` (DeBERTa), `auto` | ✅ | [Настройки и модели](#настройки-и-модели) |
| Экспериментальный контекстный E5 (`saifety context`, advisory в MCP/хуках) | ✅ | Opt-in, [#9](https://github.com/saifety-org/sAIfety/pull/9), [описание](docs/contextual-inference.md) |
| Вырезание по нормализованным координатам спанов | 🚧 | [#29](https://github.com/saifety-org/sAIfety/pull/29), задача [#24](https://github.com/saifety-org/sAIfety/issues/24) |
| Подключение контекстного кандидата к политике MCP-защиты | ⬜ | [#15](https://github.com/saifety-org/sAIfety/issues/15) |
| Проверка в реальном клиенте и решение о включении модели | ⬜ | [#16](https://github.com/saifety-org/sAIfety/issues/16) |
| **Маскирование секретов и ПДн** | | |
| Маскирование секретов (ключи, токены, JWT, пароли в URL) | ✅ | [Обезличивание](docs/configuration.md#обезличивание-redact) |
| Маскирование ПДн в ответах MCP-прокси | ✅ | [#18](https://github.com/saifety-org/sAIfety/pull/18) |
| Русские ФИО и мобильные РФ без NER | ✅ | [#20](https://github.com/saifety-org/sAIfety/pull/20), [оценка](docs/russian-pii-evaluation.md) |
| Опциональный NER (`"redact": {"ner": true}`) | ✅ | [#22](https://github.com/saifety-org/sAIfety/pull/22), [оценка](docs/optional-ner-evaluation.md) |
| Явные поля человека независимо от алфавита | 🚧 | [#23](https://github.com/saifety-org/sAIfety/pull/23), открыт |
| Маскирование e-mail в ответах MCP | 🚧 | Ветка `claude/determined-turing-cgn54s`, PR ещё не открыт |
| Опциональные детекторы СНИЛС, ИНН, паспорта, номеров карт (с контрольными суммами, за флагом) | ⬜ | Сейчас вне профиля ПДн |
| Городские и стационарные телефоны РФ (опционально, после анализа ложных срабатываний) | ⬜ | Сейчас вне профиля ПДн |
| Регресс-тесты fail-closed для всех сбоев инспекции ПДн | ⬜ | |
| Латинское имя в роли JSON-ключа в схемо-образном результате | ⬜ | Остаточный обход из ревью [#23](https://github.com/saifety-org/sAIfety/pull/23); требует NER |
| Вложенные части имени (`given`/`family`) под person-полем не удерживают весь результат | ⬜ | Связано с [#23](https://github.com/saifety-org/sAIfety/pull/23) |
| **Хуки и интеграции** | | |
| Хуки Claude Code (`session-start`, `pre-tool-use`, `post-tool-use`) и `launch` | ✅ | [Запуск Claude под защитой](docs/configuration.md#запуск-claude-под-защитой-launch-и-хуки) |
| `install`/`uninstall` для Claude Code, Claude Desktop, Cursor, Windsurf, VS Code | ✅ | [Защита MCP-клиента](#защита-mcp-клиента) |
| Разрешение `@path`-импортов и `.claude/rules/*.md` в `session-start` | ⬜ | TODO в `internal/hook/hook.go` |
| Мелкие дефекты из код-ревью (короткие строки в хуках, `.vscode/mcp.json`, окружение stdio-апстримов и др.) | ⬜ | [#28](https://github.com/saifety-org/sAIfety/issues/28) |
| **CI и релизы** | | |
| Обязательные проверки `lint`, `test`, `build` | ✅ | [#5](https://github.com/saifety-org/sAIfety/pull/5), [CI checks](#ci-checks) |
| Release workflow по тегу `v*` с `VERSION.txt` и `SHA256SUMS` | ✅ | Релизов пока нет |
| Закрепление SHA256 скачиваемых весов и ONNX Runtime | ⬜ | [#27](https://github.com/saifety-org/sAIfety/issues/27) |
| Критерии экспериментального релиза 0.0.1 | ⬜ | [#11](https://github.com/saifety-org/sAIfety/issues/11) |
| Правила подготовки и принятия PR | ⬜ | [#12](https://github.com/saifety-org/sAIfety/issues/12) |

Обозначения: ✅ — готово и смёржено в `main`; 🚧 — в работе (открыт PR или
есть несмёрженная ветка); ⬜ — не начато.

## Разработка и документация

```sh
make test
make vet
```

В этом репозитории находятся код приложения, рабочие таблицы,
тесты поведения, конфигурация и инструменты сборки, установки и выпуска.
Сборка и тесты не требуют лабораторного репозитория.

- [Конфигурация и команды](docs/configuration.md).
- [Модель prompt injection и происхождение весов](https://github.com/saifety-org/prompt-injection-model).
- Go API: [pkg/scanner](pkg/scanner) и [pkg/inference](pkg/inference).
- [saifety-org/lab](https://github.com/saifety-org/lab) — данные и обучение,
  корпуса примеров, сравнение моделей, генераторы рабочих таблиц и история проекта.

## CI checks

Pull requests and pushes to `main` run three required checks: `lint`, `test`,
`build`. Reproduce them from this repository with Go from `go.mod` and a C
compiler for the ONNX build where applicable:

```sh
make lint-install          # golangci-lint v2.14.0; installs only into ./bin
make lint                 # gofmt (read-only), go vet, configured Go linters
make ci-test              # unit/regression tests with race detector
make ci-build             # all supported build variants
```

`GOWORK=off` and `-mod=readonly` prevent local workspace overrides or implicit
module edits. Actions are pinned by commit; the linter version is pinned in
both CI and Makefile. Checks have timeouts and newer runs cancel stale runs
on the same PR. CI does not download inference models, train candidates or
run full benchmarks. ONNX integration tests requiring cached assets skip
when those assets are absent; tagged code still compiles and is linted.

The linter uses the standard checks (`errcheck`, `govet`, `ineffassign`,
`staticcheck`, `unused`) without automatic fixes. Any exclusions are narrow
rules with reasons in `.golangci.yml`. Cleanup failures already superseded by
an operation error, read-side closes and test teardown are explicitly ignored
at the call site; file writes and the final write-side close remain checked.

The application build checks native ONNX, pure-Go lite, and all five release
targets: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64 and windows/amd64.
A `v*` tag reuses the same CI workflow before publishing any release assets.

Experimental contextual E5 inference is available through the Go API and
`saifety context`, with advisory MCP/hook observation. It is opt-in and does not
change the default protection policy. See [configuration and limits](docs/contextual-inference.md).
