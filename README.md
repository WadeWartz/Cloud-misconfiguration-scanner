```text
cloud-misconfig-scanner/
├── config/
│   └── rules.yaml # Nơi lưu định nghĩa các luật quét
├── core/
│   ├── __init__.py
│   ├── auth.py # Xử lý kết nối, xác thực
│   └── engine.py # Bộ điều khiển trung tâm
├── scanners/
│   ├── __init__.py
│   ├── base_scanner.py
│   ├── s3_scanner.py
│   ├── iam_scanner.py
│   └── ec2_scanner.py
├── reporters/
│   ├── __init__.py
│   ├── json_reporter.py
│   └── html_reporter.py
├── tests/
│   ├── test_ec2.py
│   └── test_s3.py
├── .gitignore
├── README.md
├── requirements.txt
└── main.py
```
