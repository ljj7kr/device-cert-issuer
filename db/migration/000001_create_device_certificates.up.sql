CREATE TABLE IF NOT EXISTS device_certificates (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    serial_number VARCHAR(64) NOT NULL,
    device_id VARCHAR(128) NOT NULL,
    tenant_id VARCHAR(128) NOT NULL,
    subject_summary VARCHAR(512) NOT NULL,
    san_summary TEXT NOT NULL,
    fingerprint_sha256 CHAR(64) NOT NULL,
    profile VARCHAR(64) NOT NULL,
    issuance_status VARCHAR(32) NOT NULL,
    issued_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    UNIQUE KEY uq_device_certificates_serial_number (serial_number),
    UNIQUE KEY uq_device_certificates_fingerprint_sha256 (fingerprint_sha256),
    KEY idx_device_certificates_device_id (device_id),
    KEY idx_device_certificates_tenant_id (tenant_id),
    KEY idx_device_certificates_expires_at (expires_at)
)
ENGINE=InnoDB
DEFAULT CHARSET=utf8mb4
COLLATE=utf8mb4_0900_ai_ci;
