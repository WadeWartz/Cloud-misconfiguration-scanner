# SPEC.md — Cloud Misconfiguration Scanner (MVP)

## 1. Mục tiêu & Phạm vi
Xây dựng công cụ CLI bằng Python sử dụng `boto3` để quét các cấu hình sai lệch bảo mật (misconfigurations) phổ biến trên AWS (S3, IAM, EC2) dựa trên bộ luật khai báo trong `config/rules.yaml`, sau đó xuất báo cáo dạng JSON hoặc HTML.

**Phạm vi MVP:**
- Hỗ trợ 3 dịch vụ AWS: **S3**, **IAM**, **EC2**.
- Hỗ trợ quét 1 region (mặc định theo AWS profile/env hoặc `--region`) và tùy chọn nhiều region (`--regions`, trong đó S3 & IAM là global service nên chỉ quét 1 lần).
- Hỗ trợ chạy test hoàn toàn offline bằng `pytest` + `moto`.

---

## 2. Data Contracts (`core/models.py`)

### Enums
- `Severity`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
- `Status`: `PASS`, `FAIL`, `ERROR`

### `Rule` (đọc từ `config/rules.yaml`)
| Field | Type | Mô tả |
|---|---|---|
| `id` | `str` | Mã định danh duy nhất, ví dụ `S3-001` |
| `service` | `str` | `s3`, `iam`, hoặc `ec2` |
| `title` | `str` | Tên ngắn gọn của rule |
| `severity` | `Severity` | Mức độ nghiêm trọng |
| `enabled` | `bool` | Bật/tắt rule |
| `description` | `str` | Mô tả rủi ro |
| `remediation` | `str` | Hướng dẫn khắc phục |
| `params` | `dict[str, Any]` | Tham số tùy chọn (vd: `max_key_age_days`, `sensitive_ports`) |

### `Finding` (kết quả cho từng tài nguyên × từng rule)
| Field | Type | Mô tả |
|---|---|---|
| `rule_id` | `str` | Mã rule (vd `S3-001`) |
| `service` | `str` | `s3`, `iam`, `ec2` |
| `resource_id` | `str` | Tên bucket / ARN user / ID security group hoặc volume |
| `region` | `str` | Region AWS hoặc `"global"` |
| `severity` | `Severity` | Lấy từ rule |
| `status` | `Status` | `PASS`, `FAIL`, hoặc `ERROR` |
| `message` | `str` | Chi tiết ngắn gọn tại sao PASS/FAIL/ERROR |
| `remediation` | `str` | Hướng dẫn khắc phục (từ rule) |
| `timestamp` | `str` | ISO-8601 UTC timestamp |

### `ScanResult`
- `account_id`: `str` (lấy qua STS `get_caller_identity`, fallback `"unknown"`)
- `scanned_regions`: `list[str]`
- `scanned_services`: `list[str]`
- `started_at` / `finished_at`: `str` (ISO-8601 UTC)
- `findings`: `list[Finding]`
- Helper `summary()` trả về tổng số `PASS`, `FAIL`, `ERROR` và đếm `FAIL` theo từng `Severity`.

---

## 3. Danh sách Rules MVP (`config/rules.yaml`)

### S3 (`s3_scanner.py`) — Global
1. **`S3-001` (HIGH)**: Bucket chưa bật đầy đủ *Block Public Access* (cả 4 cờ `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets` phải là `True`).
2. **`S3-002` (CRITICAL)**: Bucket Policy cho phép public access (`Effect: Allow` với `Principal: "*"` hoặc `{"AWS": "*"}` và không có `Condition` hạn chế).
3. **`S3-003` (MEDIUM)**: Bucket chưa bật Default Server-Side Encryption (SSE).
4. **`S3-004` (LOW)**: Bucket chưa bật Versioning (`Status != "Enabled"`).

### IAM (`iam_scanner.py`) — Global
5. **`IAM-001` (CRITICAL)**: Root account chưa bật MFA (`AccountMFAEnabled != 1` trong `get_account_summary`).
6. **`IAM-002` (HIGH)**: IAM User có Access Key đang `Active` đã quá `max_key_age_days` ngày (mặc định `90`).
7. **`IAM-003` (CRITICAL)**: Customer-managed policy (đang gắn vào user/group/role) cấp full quyền admin (`Effect: Allow`, `Action: "*"`, `Resource: "*"`).

### EC2 (`ec2_scanner.py`) — Regional
8. **`EC2-001` (HIGH)**: Security Group mở inbound `0.0.0.0/0` hoặc `::/0` vào các port nhạy cảm (`sensitive_ports`: mặc định `[22, 3389]`).
9. **`EC2-002` (MEDIUM)**: EBS Volume chưa được mã hóa (`Encrypted == False`).
10. **`EC2-003` (MEDIUM)**: EC2 Instance chưa bắt buộc IMDSv2 (`MetadataOptions.HttpTokens != "required"`).

---

## 4. Giao diện CLI (`main.py`)

```bash
python main.py \
  --profile default \
  --region ap-southeast-1 \
  --services s3,iam,ec2 \
  --rules config/rules.yaml \
  --format html \
  --output output/report.html \
  --fail-on HIGH
```

- `--profile`: Tên AWS CLI profile (optional; nếu bỏ trống dùng chuỗi credential mặc định của `boto3`).
- `--region`: Region AWS (mặc định lấy từ session/env hoặc `us-east-1`).
- `--services`: Danh sách dịch vụ cần quét, cách nhau bằng dấu phẩy (mặc định `s3,iam,ec2`).
- `--rules`: Đường dẫn file YAML rules (mặc định `config/rules.yaml`).
- `--format`: `json`, `html`, hoặc `console` (mặc định `console`).
- `--output`: Đường dẫn file xuất báo cáo (bắt buộc khi `--format json|html`, tự tạo thư mục cha nếu chưa có).
- `--fail-on`: Thoát với exit code `1` nếu có `FAIL` từ mức severity này trở lên (hữu ích cho CI/CD).

---

## 5. Lộ trình Vibecode (Chia nhỏ để tiết kiệm token)

Thực hiện lần lượt từng bước, mỗi bước test pass rồi mới chuyển sang bước tiếp theo (có thể tạo chat mới giữa các Phase):

- **Phase 1 (Dùng model mạnh)**: Tạo `core/models.py`, `core/auth.py`, `scanners/base_scanner.py`, `scanners/s3_scanner.py`, và `tests/test_s3.py`. Chạy `python -m pytest`.
- **Phase 2 (Dùng model nhanh/trung bình)**: Tạo `scanners/iam_scanner.py`, `scanners/ec2_scanner.py`, `tests/test_iam.py`, `tests/test_ec2.py` bám theo pattern của `s3_scanner.py`.
- **Phase 3 (Dùng model nhanh/trung bình)**: Tạo `core/engine.py`, `reporters/json_reporter.py`, `reporters/html_reporter.py`, và `main.py`.
- **Phase 4 (Dùng model mạnh để review)**: Review edge cases (`AccessDenied`, pagination, multi-region), chạy toàn bộ test suite và thử nghiệm CLI.
