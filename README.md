cloud-misconfig-scanner/
│
├── config/
│   └── rules.yaml            # Nơi lưu định nghĩa các luật quét (Port nguy hiểm, S3 public...)
│
├── core/
│   ├── __init__.py
│   ├── auth.py               # Xử lý kết nối, xác thực API với AWS (Boto3 Session)
│   └── engine.py             # Bộ điều khiển trung tâm (Nạp cấu hình, gọi các module quét)
│
├── scanners/
│   ├── __init__.py
│   ├── base_scanner.py       # Lớp kế thừa (Base Class) quy định cấu trúc chung cho các scanner
│   ├── s3_scanner.py         # Module quét cấu hình sai của Amazon S3
│   ├── iam_scanner.py        # Module quét cấu hình sai của IAM (Quyền hạn, Cross-account)
│   └── ec2_scanner.py        # Module quét cấu hình sai của Security Groups (Network)
│
├── reporters/
│   ├── __init__.py
│   ├── json_reporter.py      # Xuất kết quả quét ra định dạng JSON
│   └── html_reporter.py      # Xuất kết quả quét ra file HTML (Giao diện báo cáo)
│
├── tests/                    # Thư mục chứa các hàm test code tự động (Giúp CV rất uy tín)
│   ├── test_s3.py
│   └── test_ec2.py
│
├── .gitignore                # Chặn đẩy các file nhạy cảm (như key, cache) lên GitHub
├── README.md                 # Tài liệu hướng dẫn sử dụng dự án (Giao diện của CV)
├── requirements.txt          # Danh sách thư viện cần cài đặt (boto3, pyyaml, jinja2...)
└── main.py                   # File chạy chính của chương trình (Nhận CLI arguments)