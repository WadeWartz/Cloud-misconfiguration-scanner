# Cloud Misconfiguration Scanner

Công cụ CLI viết bằng Python (`boto3` + `pyyaml`) dùng để quét các cấu hình sai lệch bảo mật (security misconfigurations) phổ biến trên AWS (**S3**, **IAM**, **EC2**) theo bộ luật khai báo trong `config/rules.yaml`, hỗ trợ xuất báo cáo ra **Console**, **JSON**, hoặc **HTML**.

---

## 1. Cấu trúc thư mục

```text
cloud-misconfig-scanner/
├── config/
│   └── rules.yaml          # Định nghĩa các luật quét (S3, IAM, EC2)
├── core/
│   ├── __init__.py
│   ├── auth.py             # Khởi tạo boto3.Session & lấy thông tin Account/Region
│   ├── engine.py           # Bộ điều khiển trung tâm (nạp rules, chạy scanners)
│   └── models.py           # Dataclasses & Enums (Rule, Finding, ScanResult, Severity, Status)
├── scanners/
│   ├── __init__.py
│   ├── base_scanner.py     # Lớp trừu tượng BaseScanner & xử lý lỗi ClientError
│   ├── s3_scanner.py       # Quét S3 (Public Access Block, Policy, Encryption, Versioning)
│   ├── iam_scanner.py      # Quét IAM (Root MFA, Access Key quá hạn, Policy *:*)
│   └── ec2_scanner.py      # Quét EC2 (Security Group mở port nhạy cảm, EBS Encryption, IMDSv2)
├── reporters/
│   ├── __init__.py
│   ├── json_reporter.py    # Xuất báo cáo JSON
│   └── html_reporter.py    # Xuất báo cáo HTML độc lập
├── tests/
│   ├── test_s3.py
│   ├── test_iam.py
│   ├── test_ec2.py
│   └── test_engine_and_cli.py
├── AGENTS.md
├── SPEC.md
├── requirements.txt
├── requirements-dev.txt
└── main.py
```

---

## 2. Yêu cầu & Cài đặt

### Yêu cầu hệ thống
* **Python**: 3.11 trở lên.
* **Tài khoản AWS**: User hoặc Role dùng để quét chỉ cần quyền **Read-Only** (khuyến nghị gắn AWS Managed Policy `SecurityAudit` hoặc `ReadOnlyAccess`).

### Các bước cài đặt

**Trên Windows (PowerShell):**
```powershell
# 1. Tạo virtual environment
python -m venv .venv

# 2. Cài đặt thư viện (dùng requirements.txt hoặc requirements-dev.txt nếu muốn chạy test)
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

**Trên Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
```

---

## 3. Hướng dẫn sử dụng

### Bước 1: Cấu hình xác thực AWS (Chọn 1 trong 2 cách)

**Cách A — Dùng AWS CLI Profile (Khuyến nghị):**
```powershell
aws configure --profile audit-readonly
```

**Cách B — Dùng biến môi trường (Environment Variables):**
```powershell
$env:AWS_ACCESS_KEY_ID="AKIA..."
$env:AWS_SECRET_ACCESS_KEY="..."
$env:AWS_DEFAULT_REGION="ap-southeast-1"
```

---

### Bước 2: Bảng tham số dòng lệnh (CLI Options)

| Tham số | Mặc định | Mô tả |
|---|---|---|
| `--profile` | *(chuỗi mặc định của boto3)* | Tên AWS CLI profile sử dụng để xác thực |
| `--region` | `us-east-1` *(hoặc theo profile)* | Quét 1 region AWS cụ thể |
| `--regions` | *(không)* | Danh sách nhiều region cách nhau bởi dấu phẩy (vd: `ap-southeast-1,us-east-1`). Ghi đè `--region` |
| `--services` | `s3,iam,ec2` | Các dịch vụ cần quét, cách nhau bởi dấu phẩy (`s3`, `iam`, `ec2`) |
| `--rules` | `config/rules.yaml` | Đường dẫn tới file YAML định nghĩa luật quét |
| `--format` | `console` | Định dạng kết quả đầu ra: `console`, `json`, hoặc `html` |
| `--output` | *(bắt buộc với `json`/`html`)* | Đường dẫn file lưu báo cáo (tự động tạo thư mục nếu chưa có) |
| `--fail-on` | *(không)* | Trả về exit code `1` nếu có lỗi `FAIL` đạt hoặc vượt mức nghiêm trọng này (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) |

---

### Bước 3: Các ví dụ chạy thực tế

#### 1. Quét toàn bộ dịch vụ và in trực tiếp ra màn hình (Console)
```powershell
.\.venv\Scripts\python.exe main.py --region ap-southeast-1
```

#### 2. Quét với một AWS Profile cụ thể và xuất báo cáo HTML trực quan
```powershell
.\.venv\Scripts\python.exe main.py `
  --profile audit-readonly `
  --region ap-southeast-1 `
  --format html `
  --output output/aws-security-report.html
```
*(Sau khi chạy xong, mở file `output/aws-security-report.html` bằng trình duyệt bất kỳ để xem bảng tổng hợp và hướng dẫn khắc phục).*

#### 3. Chỉ quét S3 và IAM, xuất kết quả ra file JSON
```powershell
.\.venv\Scripts\python.exe main.py `
  --services s3,iam `
  --format json `
  --output output/s3-iam-findings.json
```

#### 4. Quét EC2 trên nhiều Region cùng lúc
> **Lưu ý:** S3 và IAM là dịch vụ toàn cục (Global) nên công cụ sẽ tự động chỉ quét 1 lần; riêng EC2 sẽ được quét lần lượt qua từng region bạn chỉ định.
```powershell
.\.venv\Scripts\python.exe main.py `
  --regions ap-southeast-1,ap-northeast-1,us-east-1 `
  --format html `
  --output output/multi-region-report.html
```

#### 5. Tích hợp vào CI/CD Pipeline (Chặn pipeline nếu phát hiện lỗi nghiêm trọng)
Sử dụng cờ `--fail-on HIGH` để lệnh trả về mã thoát `1` khi có bất kỳ phát hiện `FAIL` nào ở mức `HIGH` hoặc `CRITICAL`:
```powershell
.\.venv\Scripts\python.exe main.py `
  --region ap-southeast-1 `
  --format json `
  --output output/ci-report.json `
  --fail-on HIGH
```

---

## 4. Danh sách các luật quét mặc định (`config/rules.yaml`)

| Rule ID | Dịch vụ | Mức độ | Nội dung kiểm tra |
|---|---|---|---|
| `S3-001` | S3 | `HIGH` | Kiểm tra cả 4 cờ *S3 Block Public Access* đã được bật hay chưa |
| `S3-002` | S3 | `CRITICAL` | Kiểm tra Bucket Policy có chứa `Effect: Allow` cho `Principal: "*"` mà không có `Condition` hay không |
| `S3-003` | S3 | `MEDIUM` | Kiểm tra S3 Bucket đã bật mã hóa mặc định (Default SSE) hay chưa |
| `S3-004` | S3 | `LOW` | Kiểm tra S3 Bucket đã bật Versioning hay chưa |
| `IAM-001` | IAM | `CRITICAL` | Kiểm tra tài khoản Root đã bật xác thực đa yếu tố (MFA) hay chưa |
| `IAM-002` | IAM | `HIGH` | Kiểm tra Access Key đang `Active` của IAM User có vượt quá ngưỡng ngày cho phép (mặc định `90` ngày) hay không |
| `IAM-003` | IAM | `CRITICAL` | Kiểm tra Customer-Managed Policy đang được gắn có cấp full quyền quản trị (`Action: "*"`, `Resource: "*"`) hay không |
| `EC2-001` | EC2 | `HIGH` | Kiểm tra Security Group có mở `0.0.0.0/0` hoặc `::/0` vào các cổng nhạy cảm (mặc định `22`, `3389`) hay không |
| `EC2-002` | EC2 | `MEDIUM` | Kiểm tra ổ đĩa EBS Volume có được mã hóa (`Encrypted: true`) hay không |
| `EC2-003` | EC2 | `MEDIUM` | Kiểm tra EC2 Instance có bắt buộc sử dụng IMDSv2 (`HttpTokens: required`) hay không |

---

## 5. Tùy chỉnh luật quét

Bạn có thể chỉnh sửa trực tiếp file `config/rules.yaml` mà không cần sửa code Python:

* **Tắt một rule không muốn quét**: Đổi `enabled: true` thành `enabled: false`.
* **Thay đổi ngưỡng tuổi tối đa của IAM Access Key (`IAM-002`)**:
  ```yaml
  params:
    max_key_age_days: 60
  ```
* **Thêm cổng nhạy cảm cần kiểm tra cho Security Group (`EC2-001`)** (ví dụ thêm MySQL `3306`, PostgreSQL `5432`, Redis `6379`):
  ```yaml
  params:
    sensitive_ports:
      - 22
      - 3389
      - 3306
      - 5432
      - 6379
  ```

---

## 6. Chạy Unit Tests & Kiểm tra chất lượng mã nguồn

Toàn bộ unit tests sử dụng thư viện `moto` để giả lập AWS hoàn toàn offline (không tốn chi phí và không cần tài khoản AWS thật):

```powershell
# Chạy toàn bộ bộ test
.\.venv\Scripts\python.exe -m pytest -v

# Kiểm tra code style & linter với Ruff
.\.venv\Scripts\python.exe -m ruff check .
```
