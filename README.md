# Jitsi Scanner

> [!WARNING]
> Проект написан ИИ. Если у вас есть вопросы, замечания или нужен другой
> сценарий работы, делайте форк и дорабатывайте под свои задачи.

Фоновый сканер на Go для поиска доменов с Jitsi Meet по обновляемому списку IP.
Список IP берется отсюда: [twl](https://github.com/openlibrecommunity/twl "openlibrecommunity/twl")
Готовый результат можно посмотреть [здесь](/found_jitsi_domains.txt "found_jitsi_domains.txt") (не обновляется)

Сканер скачивает список IP из `source_url`, собирает возможные домены через PTR,
TLS-сертификаты и HTTP/HTTPS-редиректы, затем проверяет найденные домены на
типичные признаки Jitsi Meet.

Код использует только стандартную библиотеку Go. В `go.mod` указано `go 1.20`,
поэтому проект должен собираться на Go 1.20+ и на Go 1.26.2.

## Быстрый запуск

```bash
cp config.example.json config.json
go run . --once
```

Или собрать бинарник:

```bash
go build -o jitsi-scanner .
./jitsi-scanner --once
```

Результаты пишутся сразу по мере нахождения в файл `found_jitsi_domains.txt`,
по одному домену на строку:

```text
meet.example.org
```

Файл можно смотреть еще до завершения сканирования:

```bash
tail -f found_jitsi_domains.txt
```

Подробности обнаружения пишутся в `found_jitsi_details.tsv`: домен, IP и маркер,
по которому домен был определен как Jitsi.

## Фоновый режим

```bash
./jitsi-scanner
```

В этом режиме сканер повторяет цикл с частотой из `scan_interval_seconds`.

## Конфиг

Основные параметры в `config.json`:

| Параметр | Назначение |
| --- | --- |
| `source_url` | URL со списком IP-адресов |
| `scan_interval_seconds` | Пауза между циклами сканирования |
| `output_file` | Файл с найденными доменами |
| `details_file` | TSV-файл с доменом, IP и причиной обнаружения |
| `state_file` | JSON-файл с состоянием последнего запуска |
| `log_file` | Файл логов |
| `max_workers` | Количество параллельных воркеров |
| `connect_timeout_seconds` | Таймаут TCP/TLS-подключений |
| `request_timeout_seconds` | Таймаут HTTP-запросов |
| `verify_tls` | Проверять TLS-сертификаты при HTTP-проверках |
| `probe_http` | Проверять HTTP |
| `probe_https` | Проверять HTTPS |
| `require_domain_resolves_to_ip` | Проверять, что найденный домен резолвится в сканируемый IP |
| `force_probe_ip` | Подключаться к найденному домену именно через проверяемый IP, сохраняя правильный `Host` и SNI |
| `follow_cross_host_redirects` | Разрешать засчитывать редиректы на другой домен. По умолчанию выключено |
| `candidate_limit_per_ip` | Лимит доменов-кандидатов на один IP |
| `jitsi_paths` | Пути, которые проверяются на домене |

Создать конфиг со значениями по умолчанию:

```bash
./jitsi-scanner --write-default-config
```

## Меньше ложных срабатываний

По умолчанию включены два защитных режима:

```json
"force_probe_ip": true,
"follow_cross_host_redirects": false
```

Это означает, что если домен найден в сертификате или редиректе IP-адреса,
проверочный GET-запрос будет выполнен именно к этому IP, но с доменным `Host`.
Редирект на другой домен не будет считаться найденным Jitsi.

Если после обновления алгоритма в `found_jitsi_domains.txt` уже есть старые
ложные домены, перед новым запуском можно очистить результат:

```bash
rm -f found_jitsi_domains.txt found_jitsi_details.tsv scanner_state.json
./jitsi-scanner --once
```

## systemd

1. Скопируйте проект, например в `/opt/jitsi-scanner`.
2. Соберите бинарник:

```bash
cd /opt/jitsi-scanner
go build -o jitsi-scanner .
cp config.example.json config.json
```

3. Создайте пользователя и выдайте ему права на каталог:

```bash
sudo useradd --system --home /opt/jitsi-scanner --shell /usr/sbin/nologin jitsi-scanner
sudo chown -R jitsi-scanner:jitsi-scanner /opt/jitsi-scanner
```

4. Установите сервис:

```bash
sudo cp contrib/jitsi-scanner.service /etc/systemd/system/jitsi-scanner.service
sudo systemctl daemon-reload
sudo systemctl enable --now jitsi-scanner
sudo journalctl -u jitsi-scanner -f
```

## Ограничения

По одному IP не всегда можно надежно получить все домены, которые на нем
обслуживаются. Сканер использует практичные источники кандидатов: PTR, домены из
сертификата по умолчанию и редиректы с IP. Если нужный домен доступен только при
точном SNI/Host и нигде не раскрывается, его нельзя обнаружить только из IP.
