# device-cert-issuer

`device-cert-issuer` 는 온라인 device certificate issuance service 다  
이 서비스는 device 가 생성한 CSR 을 검증하고, 이미 발급된 Intermediate CA 인증서와 signing capability 를 사용해 mTLS 용 device certificate 를 발급한다

## 아키텍처 개요

- `api/openapi.yaml`
  OpenAPI 계약
- `cmd/device-cert-issuer`
  프로세스 시작점과 dependency wiring
- `internal/transport/http`
  `net/http` 기반 transport 와 OpenAPI server binding
- `internal/service`
  request validation, enrollment authorization, CSR validation, issuance policy
- `internal/repository`
  저장 추상화
- `internal/repository/mysql`
  `sqlc` generated query 래퍼
- `internal/infra/signer`
  `crypto.Signer` 기반 signer abstraction 과 file signer
- `internal/infra/pemutil`, `internal/infra/serial`, `internal/infra/clock`
  PKI 보조 유틸리티

의존 방향은 `transport -> service -> repository/domain` 이고, infra 는 하위 구현 세부사항으로 분리했다

## 디렉터리 트리

```text
.
├── api
│   └── openapi.yaml
├── build
│   └── oapi-codegen.yaml
├── cmd
│   └── device-cert-issuer
│       └── main.go
├── db
│   ├── migration
│   │   ├── 000001_create_device_certificates.down.sql
│   │   └── 000001_create_device_certificates.up.sql
│   └── query
│       └── device_certificates.sql
├── internal
│   ├── app
│   ├── config
│   ├── domain
│   ├── gen
│   │   ├── openapi
│   │   └── sqlc
│   ├── infra
│   │   ├── clock
│   │   ├── pemutil
│   │   ├── serial
│   │   ├── signer
│   │   └── storage
│   ├── repository
│   │   └── mysql
│   ├── service
│   └── transport
│       └── http
├── Makefile
├── docker-compose.yml
├── go.mod
└── sqlc.yaml
```

## 보안 결정

- CSR subject 와 extension 을 신뢰하지 않고 서버에서 certificate template 를 재구성한다
- CSR signature 검증으로 proof of possession 을 확인한다
- CA intent 가 있는 CSR 과 허용되지 않은 SAN 타입을 거부한다
- signer 는 `crypto.Signer` 로 추상화해서 file signer 에서 KMS/HSM signer 로 교체하기 쉽게 유지한다
- file signer 는 `-----BEGIN ENCRYPTED PRIVATE KEY-----` 형식의 encrypted PKCS#8 private key 만 허용한다
- file signer 는 `PBES2 + PBKDF2-HMAC-SHA256 + AES-256-CBC` 암호화 프로파일만 허용한다
- legacy OpenSSL PEM encryption (`Proc-Type`, `DEK-Info`) 은 지원하지 않는다
- 발급 만료일은 Intermediate CA 인증서의 만료일을 넘지 못한다
- request body size 와 HTTP timeout 을 명시적으로 제한한다
- private key 내용과 raw CSR 은 로그에 남기지 않는다
- file signer 는 private key 파일 권한이 과도하면 초기화에 실패한다

## OpenAPI 예시

요청

```json
{
  "device_id": "device-001",
  "tenant_id": "tenant-a",
  "model": "sensor-v2",
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----",
  "profile": "default"
}
```

응답

```json
{
  "device_certificate_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "certificate_chain_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "serial_number": "7F1A...",
  "not_before": "2026-03-20T00:00:00Z",
  "not_after": "2026-04-19T00:00:00Z"
}
```

## 환경 변수

필수 값

- `MYSQL_DSN`
- `INTERMEDIATE_CERT_PATH`
- `INTERMEDIATE_PRIVATE_KEY_PATH` when `SIGNER_MODE=file`
- `INTERMEDIATE_PRIVATE_KEY_PASSPHRASE` when `SIGNER_MODE=file`

주요 값

- `SERVER_PORT`
- `SERVER_READ_TIMEOUT`
- `SERVER_READ_HEADER_TIMEOUT`
- `SERVER_WRITE_TIMEOUT`
- `SERVER_IDLE_TIMEOUT`
- `SERVER_REQUEST_BODY_LIMIT`
- `SIGNER_MODE`
- `INTERMEDIATE_CHAIN_PATH`
- `CERT_VALIDITY`
- `ALLOWED_KEY_ALGORITHMS`
- `ALLOWED_CURVES`
- `ALLOWED_RSA_BITS`
- `ALLOWED_PROFILES`
- `DEFAULT_PROFILE`
- `LOG_LEVEL`

## 로컬 실행

MySQL 실행

```bash
docker compose up -d
```

`docker compose up -d` 는 `mysql-migrate` service 를 같이 실행해서 `device_certificates` 테이블이 없으면 자동으로 생성한다  
기존 volume 이 있어도 `CREATE TABLE IF NOT EXISTS` 로 안전하게 재실행된다

환경 변수 예시

```bash
cp .env.example .env
```

`.env` 값을 실제 경로에 맞게 수정한 뒤 서비스 실행

file signer mode 는 아래 persisted key format 만 지원한다

```pem
-----BEGIN ENCRYPTED PRIVATE KEY-----
...
-----END ENCRYPTED PRIVATE KEY-----
```

지원하는 암호화 프로파일

- `PBES2`
- `PBKDF2`
- `HMAC-SHA256`
- `AES-256-CBC`

다음 legacy 형식은 지원하지 않는다

- `Proc-Type: 4,ENCRYPTED`
- `DEK-Info: ...`
- `-----BEGIN RSA PRIVATE KEY-----`
- `-----BEGIN EC PRIVATE KEY-----`
- `-----BEGIN PRIVATE KEY-----`

```bash
make run
```

Swagger UI 는 `http://localhost:8080/swagger` 에서 확인할 수 있다  
raw OpenAPI spec 는 `http://localhost:8080/openapi.yaml` 로 노출된다

## File Signer 운영 가이드

file signer mode 는 encrypted PKCS#8 를 강제한다  
PKCS#8 는 persisted key format 을 하나로 고정해서 운영 복잡도를 낮추고, legacy PEM encryption 호환 코드를 제거할 수 있어서 local signer 보안 경계를 더 명확하게 만든다  
`PBES2 + PBKDF2-HMAC-SHA256 + AES-256-CBC` 로 프로파일을 고정하면 운영자가 예상하지 못한 KDF/cipher 변형이 들어오는 것을 막을 수 있다

legacy OpenSSL PEM encrypted key 를 쓰고 있다면 먼저 변환해야 한다

```bash
openssl pkcs8 \
  -in legacy-intermediate.key.pem \
  -topk8 \
  -v2prf hmacWithSHA256 \
  -v2 aes-256-cbc \
  -out intermediate.key.pkcs8.pem
```

변환 결과는 반드시 `-----BEGIN ENCRYPTED PRIVATE KEY-----` 로 시작해야 한다

운영자 migration note

- 기존 key 가 `Proc-Type` 또는 `DEK-Info` 헤더를 쓰면 그대로는 기동되지 않는다
- 기존 key 가 `RSA PRIVATE KEY`, `EC PRIVATE KEY`, `PRIVATE KEY` PEM 이면 그대로는 기동되지 않는다
- 기존 encrypted PKCS#8 라도 `PBES2 + PBKDF2-HMAC-SHA256 + AES-256-CBC` 가 아니면 그대로는 기동되지 않는다
- Intermediate CA certificate 와 private key 가 불일치하면 signer 초기화가 실패한다
- future KMS/HSM signer mode 는 local persisted private key file 을 직접 읽지 않는 방향으로 분리된다

## 코드 생성

OpenAPI

```bash
make generate-openapi
```

직접 실행

```bash
go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.5.0 --config build/oapi-codegen.yaml api/openapi.yaml
```

sqlc

```bash
make generate-sqlc
```

직접 실행

```bash
go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.30.0 generate
```

## 품질 확인

Lint

```bash
make lint
```

Test

```bash
GOCACHE=$(pwd)/.gocache go test ./...
```

Coverage

```bash
GOCACHE=$(pwd)/.gocache make test-cover
```

## 가정

- enrollment authorization baseline 은 static policy 로 두고 이후 외부 enrollment system 연동 지점을 `EnrollmentAuthorizer` 로 열어둠
- 현재 chain 응답은 Intermediate CA PEM 또는 configured chain PEM 을 반환
- `internal/gen/openapi` 와 `internal/gen/sqlc` 는 reproducible generation 을 위한 baseline 생성본 역할도 겸한다
