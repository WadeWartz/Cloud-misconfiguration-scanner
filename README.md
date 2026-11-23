# Cloud Misconfiguration Scanner

Công cụ CLI viết bằng Python (`boto3` + `pyyaml`) dùng để quét các cấu hình sai lệch bảo mật (security misconfigurations) phổ biến trên AWS (**S3**, **IAM**, **EC2**) theo bộ luật khai báo trong `config/rules.yaml`, hỗ trợ xuất báo cáo ra Console, **JSON**, hoặc **HTML**.

## Cấu trúc thư mục

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

## Cài đặt

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

## Sử dụng CLI

```powershell
# Quét và in kết quả ra console
.\.venv\Scripts\python.exe main.py --region ap-southeast-1

# Quét S3 & IAM và xuất báo cáo HTML
.\.venv\Scripts\python.exe main.py --services s3,iam --format html --output output/report.html

# Quét toàn bộ dịch vụ, xuất JSON và trả về exit code 1 nếu có lỗi từ mức HIGH trở lên (dùng cho CI/CD)
.\.venv\Scripts\python.exe main.py --profile default --region ap-southeast-1 --format json --output output/report.json --fail-on HIGH
```

## Kiểm thử (Offline với `moto`)

```powershell
.\.venv\Scripts\python.exe -m pytest -v
.\.venv\Scripts\python.exe -m ruff check .
```
