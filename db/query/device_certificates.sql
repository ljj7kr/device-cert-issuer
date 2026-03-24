-- name: CreateDeviceCertificate :execresult
INSERT INTO device_certificates (
    serial_number,
    device_id,
    tenant_id,
    subject_summary,
    san_summary,
    fingerprint_sha256,
    profile,
    issuance_status,
    issued_at,
    expires_at,
    created_at,
    updated_at
) VALUES (
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?
);

-- name: GetDeviceCertificateBySerialNumber :one
SELECT
    id,
    serial_number,
    device_id,
    tenant_id,
    subject_summary,
    san_summary,
    fingerprint_sha256,
    profile,
    issuance_status,
    issued_at,
    expires_at,
    created_at,
    updated_at
FROM device_certificates
WHERE serial_number = ?
LIMIT 1;
