# Jitsi Scanner

> [!WARNING]
> Проект написан ИИ. Если у вас есть вопросы, замечания или нужен другой
> сценарий работы, делайте форк и дорабатывайте под свои задачи.

Фоновый сканер на Go для поиска доменов с Jitsi Meet по обновляемому списку IP.
Список IP берется отсюда: [twl](https://github.com/openlibrecommunity/twl "openlibrecommunity/twl").
Готовый результат можно посмотреть [здесь](/found_jitsi_domains.txt "found_jitsi_domains.txt")
(не обновляется автоматически в репозитории).

Сканер скачивает список IP из `source_url`, собирает возможные домены через PTR,
TLS-сертификаты и HTTP/HTTPS-редиректы, затем проверяет найденные домены на
типичные признаки Jitsi Meet.

Код использует только стандартную библиотеку Go. В `go.mod` указано `go 1.20`,
поэтому проект должен собираться на Go 1.20+.

## Что понадобится

1. Установленный Go 1.20 или новее.
2. Скопированный проект на сервер или компьютер.
3. Терминал в папке проекта.

Проверить Go:

```bash
go version
```

## Быстрый запуск

Создайте конфиг:

```bash
cp config.example.json config.json
```

Запустите один цикл сканирования:

```bash
go run . --once
```

Или сначала соберите программу:

```bash
go build -o jitsi-scanner .
./jitsi-scanner --once
```

Найденные домены сразу записываются в `found_jitsi_domains.txt`, по одному
домену на строку:

```text
meet.example.org
```

Подробности записываются в `found_jitsi_details.tsv`: домен, IP и маркер, по
которому домен был определен как Jitsi.

## Простой запуск в фоне

Этот способ подходит большинству пользователей на Linux-сервере.

1. Перейдите в папку проекта:

```bash
cd /path/to/jitsi-scanner
```

2. Создайте конфиг, если его еще нет:

```bash
cp config.example.json config.json
```

3. Соберите программу:

```bash
go build -o jitsi-scanner .
```

4. Запустите сканер в фоне:

```bash
nohup ./jitsi-scanner > scanner.out 2>&1 &
```

После этого терминал можно закрыть. Сканер продолжит работать в фоне и будет
повторять сканирование с интервалом из `scan_interval_seconds`.

Проверить, что процесс запущен:

```bash
ps aux | grep jitsi-scanner
```

Смотреть общий лог запуска:

```bash
tail -f scanner.out
```

Смотреть найденные домены:

```bash
tail -f found_jitsi_domains.txt
```

Остановить фоновый процесс:

```bash
pkill -f jitsi-scanner
```

## Запуск через systemd

Этот способ удобнее для постоянной работы на сервере: сканер будет запускаться
после перезагрузки и автоматически перезапускаться при ошибке.

1. Скопируйте проект, например в `/opt/jitsi-scanner`.

2. Соберите бинарник и создайте конфиг:

```bash
cd /opt/jitsi-scanner
go build -o jitsi-scanner .
cp config.example.json config.json
```

3. Создайте системного пользователя и выдайте права на папку:

```bash
sudo useradd --system --home /opt/jitsi-scanner --shell /usr/sbin/nologin jitsi-scanner
sudo chown -R jitsi-scanner:jitsi-scanner /opt/jitsi-scanner
```

4. Установите сервис:

```bash
sudo cp contrib/jitsi-scanner.service /etc/systemd/system/jitsi-scanner.service
sudo systemctl daemon-reload
sudo systemctl enable --now jitsi-scanner
```

Проверить статус:

```bash
sudo systemctl status jitsi-scanner
```

Смотреть лог:

```bash
sudo journalctl -u jitsi-scanner -f
```

Остановить сервис:

```bash
sudo systemctl stop jitsi-scanner
```

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
| `force_probe_ip` | Подключаться к найденному домену через проверяемый IP, сохраняя правильный `Host` и SNI |
| `follow_cross_host_redirects` | Разрешать засчитывать редиректы на другой домен |
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

## Ограничения

По одному IP не всегда можно надежно получить все домены, которые на нем
обслуживаются. Сканер использует практичные источники кандидатов: PTR, домены
из сертификата по умолчанию и редиректы с IP. Если нужный домен доступен только
при точном SNI/Host и нигде не раскрывается, его нельзя обнаружить только из IP.
