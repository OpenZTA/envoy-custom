# OpenZTA Proxy: комплект запуска

Комплект запускает нативный OpenZTA Proxy с обязательным клиентским mTLS и непрерывной авторизацией. Политики и сертификаты выдаёт существующая платформа OpenZTA. В образе нет PKI, приватных ключей, тестовых пользователей или разрешающих политик.

## Состав выпуска

* `openzta-proxy-image.tar` — образ для автономной загрузки через `docker load`.
* `release-manifest.json` — идентификатор и архитектура образа, хеш бинарника, патчей и файлов, результаты runtime-приёмки, статус C++-набора.
* `runtime-acceptance.json` — проверки именно этого образа.
* `sbom.cdx.json` — CycloneDX: пакеты ОС и зависимости разрешённого графа сборки.
* `build-dependencies.json` — происхождение зависимостей и явный список репозиториев, для которых нет метаданных версии.
* `SHA256SUMS` — контрольные суммы файлов комплекта.

Полный C++-набор можно отложить явным выбором `runtime-candidate`. Это записывается в образ и манифест. Стандартная финальная цель Dockerfile — `verified` — сохраняет полный C++ gate.

```sh
docker build --target runtime-candidate \
  --build-arg BUILD_JOBS=3 \
  --build-arg BUILD_SCM_REVISION="$(git rev-parse HEAD)" \
  -f docker/Dockerfile -t openzta-proxy:candidate .

cd test/acceptance
OPENZTA_ENVOY_IMAGE=openzta-proxy:candidate go test -race -count=1 -timeout=5m ./...
```

Выпуск привязан к архитектуре из манифеста. Для другой архитектуры собирается отдельный образ и повторяется приёмка. Проверка конфигурации не заменяет runtime-приёмку.

## Подготовка ресурса

В NAC должны существовать ресурс, разрешающая политика и зарегистрированная клиентская идентичность. `resource_host` в конфигурации — идентификатор ресурса NAC. Он не выбирается заголовком Host клиента.

`example.json` содержит HTTPS/HTTP/2, WebSocket/SSE, gRPC и WebTransport. Укажите свои значения:

| Поле | Назначение |
|---|---|
| `app.example.org` | Публичное имя и идентификатор ресурса NAC |
| `nac.internal:8181` | Защищённый endpoint авторизации `/api/v1/verify` |
| `app.internal:8080` | Приватный HTTP upstream |
| `app.internal:50051` | Приватный HTTP/2 gRPC upstream |
| `app.internal:9443` | Приватный WebTransport upstream через mTLS |

Для WebTransport включены `webtransport` и `webtransport-h3`. В этом профиле одна сессия занимает отдельное QUIC-соединение. Дочерние BIDI/UNI-потоки и дейтаграммы принадлежат одной авторизованной сессии. Отзыв политики, сертификата или недоступность авторизации закрывают её. Надёжные потоки используют backpressure; дейтаграммы при перегрузке могут теряться и не складываются в неограниченную очередь.

Браузерная проверка требует поддержки WebTransport с клиентским сертификатом в браузере. Нативный `labprobe` позволяет проверить транспорт с явно заданным сертификатом. Поддержку конкретного браузера следует проверять отдельно от поддержки транспорта прокси.

Файлы PKI предоставляются отдельно:

```text
secrets/
  gateway.crt       # цепочка сервисного сертификата прокси
  gateway.key       # приватный ключ; доступен только runtime UID/группе
  client-ca.pem     # доверенные CA клиентских идентичностей
  nac-ca.pem        # CA сервера NAC
  upstream-ca.pem   # CA приватного WebTransport сервиса
```

Сервисный сертификат прокси должен подходить для TLS server и TLS client. Приватный WebTransport сервис проверяет CA и разрешённую сервисную идентичность прокси. Для LAB это `LAB_WEBTRANSPORT_PROXY_DNS`; значение должно совпадать с DNS SAN сервисного сертификата. Сертификат приложения должен иметь SAN `app.internal`. Origin браузера проверяется приложением по публичному имени ресурса; маршрут WebTransport в примере сохраняет публичную authority.

Приватные ключи не помещаются в образ или комплект выпуска. `prepare.py` монтирует отдельные файлы, на которые действительно ссылается конфигурация. Ключи CA и сертификаты других пользователей в контейнер не попадают.

## Сети и запуск

Приложение находится в отдельной внутренней сети. На его HTTP/TCP/UDP-портах не должно быть публикации на хост. Прокси подключается к сети приложения и сети NAC/входного балансировщика. Маршрутизация IPv4/IPv6 через контейнер выключена.

Создайте сети либо используйте существующие сети платформы:

```sh
docker network create openzta-edge
docker network create --internal openzta-protected
```

Подключите приложение с DNS alias `app.internal` к `openzta-protected`, NAC с DNS alias `nac.internal` — к `openzta-edge`. Для нескольких ресурсов используйте отдельные сети приложения и явные маршруты.

Проверьте архив и загрузите образ:

```sh
sha256sum -c SHA256SUMS
docker load -i openzta-proxy-image.tar
```

`IMAGE` — неизменяемый `sha256:…` из манифеста либо `registry/repository@sha256:…`. Каталог `secrets` должен быть читаемым выбранным непривилегированным UID. На Linux приватный ключ обычно принадлежит `10001:10001` и имеет режим `0600` либо `0640`.

```sh
python3 prepare.py \
  --bootstrap ./example.json --pki ./secrets \
  --image "$IMAGE" \
  --edge-network openzta-edge --protected-network openzta-protected \
  --port-map 8443=443 --out ./deployment

docker compose -p openzta-proxy -f ./deployment/compose.json up -d
```

Публикация по умолчанию — `127.0.0.1`. Для публикации на выбранном адресе добавьте `--bind ADDRESS`; подключение внешних клиентов обычно выполняет L4-балансировщик. HTTPS использует TCP и UDP на одном публичном порту. Порт в Alt-Svc должен совпадать с публичным UDP-портом.

Preflight проверяет mTLS, запрет fail-open, повторную проверку политик, порядок фильтров, доверенные CA и точные SAN NAC/WebTransport, внутреннюю сеть backend, сроки сертификатов, права файлов и валидность конфигурации реальным бинарником под runtime UID. В `deployment-manifest.json` записываются результаты. Запуск не выдаёт доступ пользователям и не меняет NAC-политики.

Ограничения по умолчанию: контейнер 1 GiB, heap budget 768 MiB, два worker, ограниченные pending requests, буферы и очереди. Файловая система read-only, capabilities отсутствуют, `/tmp` — отдельный ограниченный tmpfs. Значения меняются параметрами `prepare.py` и конфигурацией upstream на основании измерений нагрузки.

## Проверка после запуска

```sh
docker compose -p openzta-proxy -f deployment/compose.json exec -T proxy \
  curl --fail --silent --unix-socket /tmp/envoy-admin.sock http://localhost/ready
```

Admin API доступен через Unix socket внутри контейнера. Его не следует публиковать наружу. Docker healthcheck использует `/ready`.

Приёмка защищённого LAB выполняется реальными клиентами:

```sh
labprobe -suite http3 -url https://app.example.org \
  -ca ./server-ca.pem -cert ./client.crt -key ./client.key
labprobe -suite webtransport -url https://app.example.org \
  -ca ./server-ca.pem -cert ./client.crt -key ./client.key
labprobe -suite webtransport -session -webtransport-mode mixed \
  -session-duration 0 -eps 1 -messages 0 \
  -url https://app.example.org -ca ./server-ca.pem -cert ./client.crt -key ./client.key \
  -out webtransport-session.json
```

Для LAB маршрут WebTransport должен вести на `/api/lab/webtransport`; замените `/webtransport` в примере. Его приватный HTTP-порт также должен совпадать с настройкой LAB. `labprobe` проверяет реальные echo/stream endpoints LAB; для бизнес-приложения используйте его собственные операции.

При отзыве доступа проверяйте одновременно закрытие открытой сессии, отказ нового подключения, прекращение событий backend и решение NAC с тем же session ID. Одно сообщение клиента об обрыве не доказывает отзыв политики.

Эксплуатация, обновление и возврат версии описаны в `OPERATIONS.ru.md`.

## Доказательства сборки и экспорт

`dependency_inventory.py` принимает результат `bazel cquery 'deps(//:envoy)'`
с той же конфигурацией `-c opt --config=openzta`, resolved
`repository_locations.bzl` и `--build-evidence` — отчёт упаковки с `state: passed`,
неизменяемым `image_id`, `native_input_hashes` и `native_patch_hashes`. Отчёт
упаковки должен быть создан после успешного линкования и проверки неизменности
входов сборки. В inventory сохраняются image ID, хеши исходников и патчей,
покрытые зависимости и явный список репозиториев без метаданных версии.

`export_release.py --image IMAGE --evidence RUNTIME_REPORT --dependencies INVENTORY
--cpp-status deferred --out NEW_DIRECTORY` экспортирует только образ с успешной
runtime-приёмкой и совпадающими хешами текущих исходников, патчей и inventory.
`RUNTIME_REPORT` содержит `state: passed`, тот же `image_id`, хеши нативных входов
и непустой список `results` с успешными проверками. В `results` записывают только
фактически выполненные проверки; пропуски и запуск без `OPENZTA_ENVOY_IMAGE` не
являются успешной runtime-приёмкой. `deferred` сохраняет явный пропуск полного
C++ набора; для обычного выпуска используйте `passed` после его выполнения.
Образы и архивы не публикуются автоматически в registry.
