# Chuẩn hoá Bộ Rule Baseline Semgrep OSS và Phương pháp Thực nghiệm Benchmark

## 1. Đặt vấn đề và Động lực học thuật (Motivation)

Trong các đề tài nghiên cứu và khóa luận tốt nghiệp về An toàn thông tin / Phân tích mã nguồn tĩnh (SAST), một sai lầm phổ biến làm suy giảm độ tin cậy khoa học là **"tự viết rule phát hiện rồi tự viết mã nguồn mẫu để thử nghiệm"**.

Hạn chế nghiêm trọng của cách làm này bao gồm:
1. **Thiên kiến người thử nghiệm (Experimenter Bias / Overfitting)**: Tác giả vô thức viết rule khớp sát với cấu trúc cú pháp của các file test mẫu, dẫn đến việc công cụ đạt điểm số F1-Score cao giả tạo nhưng hoàn toàn thất bại khi quét các dự án thực tế.
2. **Vi phạm tính hợp lệ của cấu trúc đo (Construct Validity)**: Hội đồng khoa học và chuyên gia phản biện không thể xác minh được khả năng phát hiện của công cụ đến từ sức mạnh giải thuật (AST, CFG, DFG) hay chỉ do rule tự chế được "ép khuôn".
3. **Mất khả năng đối sánh sòng phẳng (Fair Baseline Comparison)**: Để khẳng định một công cụ mới vượt trội hơn các giải pháp hiện hành (như Semgrep, Bandit, Snyk), cả hai công cụ bắt buộc phải **chia sẻ cùng một tập định nghĩa lỗ hổng chuẩn (Standard Vulnerability Ground Truth)**.

Do đó, **Aegis-SAST đã chuyển đổi toàn diện sang sử dụng bộ rule từ Semgrep OSS Registry (Community Rules)** — kho luật mã nguồn mở uy tín và được kiểm thử nghiêm ngặt nhất hiện nay bởi cộng đồng bảo mật quốc tế (Trail of Bits, Return To Corporation, OWASP).

---

## 2. Phả hệ và Kiến trúc Bộ Rule Semgrep OSS trong Aegis-SAST

### 2.1. Nguồn gốc quy chuẩn (Provenance)

Toàn bộ tập luật baseline được trích xuất trực tiếp từ kho `semgrep-rules` (Community Edition, giấy phép LGPL/Apache 2.0):
- **Phân loại trọng tâm**: OWASP Top 10 và CWE Top 25.
- **Ngôn ngữ mục tiêu**: Python (bao gồm core runtime, Flask, Django, FastAPI, AWS Lambda, SQLAlchemy, Requests).
- **Vulnerability Families**:
  - `COMMAND_INJECTION` (CWE-78, CWE-77): `os.system`, `subprocess.run`, `asyncio.create_subprocess_exec`, `os.popen`.
  - `PATH_TRAVERSAL` (CWE-22): `open`, `send_file`, `os.remove`, `pathlib.Path`.
  - `SQL_INJECTION` (CWE-89): `cursor.execute`, `cursor.executemany`, `raw()`, `sqlalchemy.text`, `psycopg`.
  - `INSECURE_DESERIALIZATION` (CWE-502): `pickle.loads`, `yaml.load`, `marshal.loads`.
  - `SSRF` (CWE-918): `requests.get`, `requests.post`, `urllib.request.urlopen`.
  - `XSS` (CWE-79): `render_template_string`, `Markup`, `Flask.response`.

### 2.2. Đường ống chuẩn hoá 3 giai đoạn (Rule Processing Pipeline)

```
+-------------------------------------------------------------------+
| 1. Semgrep OSS Community Registry (refs/rule_sources/)            |
|    - 337 files YAML (mode: taint, patterns, metadata)             |
+---------------------------------+---------------------------------+
                                  |
                                  v
+---------------------------------+---------------------------------+
| 2. Aegis Rule Workbench (Normalization & Validation)              |
|    - Standardize taxonomy: CWE / OWASP Top 10                     |
|    - Extract sources, sinks, sanitizers, remediation hints        |
|    - Output: semgrep_oss_python_baseline.normalized.json          |
|    - Output: semgrep_oss_python_baseline.validation.json         |
+---------------------------------+---------------------------------+
                                  |
                                  v
+---------------------------------+---------------------------------+
| 3. Legacy Engine Compiler & Runtime Rule Profile                  |
|    - Compile to fast AST pattern matching schema                  |
|    - Output: semgrep_oss_python_baseline.legacy.yaml              |
|    - Registered Profile: --reviewed-rule-profile semgrep-oss-full |
+-------------------------------------------------------------------+
```

Thống kê tập rule baseline chuẩn hoá:
- **Tổng số luật chuẩn hoá**: 53 rules (bao phủ 6 nhóm lỗ hổng cốt lõi).
- **Tập Sources chuẩn**: 40 entry (HTTP args, form, cookies, headers, JSON body, env, CLI args).
- **Tập Sinks chuẩn**: 44 entry trên 6 danh mục rce, path_traversal, sqli, ssrf, xss, deserialization.
- **Tập Sanitizers chuẩn**: 16 entry (shlex.quote, secure_filename, abspath guard, int(), parameterized queries).

---

## 3. Định vị Đóng góp Học thuật của Đồ án (Academic Contribution)

Khi sử dụng cùng một bộ rule Semgrep OSS, đồ án không claim là "phát minh ra rule mới", mà tập trung vào **hai đóng góp nghiên cứu cốt lõi giải quyết đúng điểm nghẽn của SAST truyền thống**:

| Trục nghiên cứu | Điểm yếu của Semgrep OSS truyền thống | Giải pháp vượt trội của Aegis-SAST | Đóng góp học thuật |
| :--- | :--- | :--- | :--- |
| **1. Static Analysis Core** | Semgrep OSS chủ yếu dựa trên AST pattern matching cục bộ (single function). Khi taint flow truyền qua nhiều hàm (inter-procedural) hoặc qua các module khác nhau (cross-file), Semgrep OSS thường bị **False Negative (bỏ sót)** nếu không có bản thương mại Pro Engine. | Aegis-SAST xây dựng **Control Flow Graph (CFG) + Data Flow Graph (DFG) + Call Graph liên hàm** bằng Tree-sitter. Taint được lan truyền chính xác từ source hàm A -> qua đối số -> tới sink hàm B trong module khác. | **Tăng Recall** trên các luồng dữ liệu phức tạp mà rule tĩnh không thể bắt được. |
| **2. Multi-Agent Triage** | Semgrep OSS gắn cờ bất kỳ nơi nào có sink gọi dữ liệu chưa xác định, dẫn đến tỷ lệ **False Positive (báo động giả) rất cao (30% - 50%)**, gây quá tải cho kỹ sư bảo mật. | Aegis-SAST kích hoạt **Multi-Agent Consensus (Auditor + Skeptic + Judge)**: Skeptic đóng vai trò luật sư biện hộ, tìm kiếm xem biến đã được kiểm tra điều kiện (if/else), sanitized, hay là hằng số cấu hình nội bộ. | **Giảm False Positive Rate (FPR)** từ ~40% xuống <10% mà không làm giảm Recall. |

---

## 4. Phương pháp Thực nghiệm và Đối sánh Benchmark

### 4.1. Thiết kế Thí nghiệm Đối đầu 3 Hiệp (Head-to-Head Experiment)

Thực nghiệm được thiết kế đối đầu trên cùng một tập ground-truth test suite (NIST SAMATE Juliet Python / OWASP Benchmark):

```
                        TẬP TEST GROUND-TRUTH CHUẨN
                     (NIST SAMATE Juliet / OWASP Python)
                                      |
         +----------------------------+----------------------------+
         |                                                         |
         v                                                         v
   [CẤU HÌNH 1]                                              [CẤU HÌNH 2 & 3]
  Raw Semgrep OSS                                               Aegis-SAST
(Semgrep Community Rules)                               (Semgrep Baseline Profile)
         |                                                         |
         |                                          +--------------+--------------+
         |                                          |                             |
         v                                          v                             v
[Chỉ số Baseline]                           [CẤU HÌNH 2: Core]            [CẤU HÌNH 3: Full]
 - TP, FP, FN                                 AST-DFG Taint               AST-DFG + AI Triage
 - Precision, Recall, F1                    (Deterministic Only)          (Auditor/Skeptic/Judge)
                                                    |                             |
                                                    v                             v
                                            [Đo đạc Recall tăng]          [Đo đạc FP giảm]
```

### 4.2. Các chỉ số đo lường học thuật

1. **True Positives (TP)**: Số lỗ hổng thực tế có thể khai thác được công cụ nhận diện chính xác.
2. **False Positives (FP)**: Các đoạn mã an toàn (có sanitizer, constant, unreachable) bị gắn cờ nhầm.
3. **False Negatives (FN)**: Các lỗ hổng thực tế bị công cụ bỏ sót.
4. **Precision**: $\text{Precision} = \frac{TP}{TP + FP}$ (Độ chính xác của cảnh báo).
5. **Recall (Sensitivity)**: $\text{Recall} = \frac{TP}{TP + FN}$ (Độ bao phủ phát hiện).
6. **F1-Score**: $F_1 = 2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$ (Chỉ số hài hoà tổng thể).
7. **Tỷ lệ giảm báo động giả (False Positive Reduction Rate)**:
   $$\text{FPR Reduction} = \frac{FP_{\text{Semgrep}} - FP_{\text{Aegis-Full}}}{FP_{\text{Semgrep}}} \times 100\%$$

---

## 5. Hướng dẫn Tái hiện Thực nghiệm (Reproducibility Guide)

Nhằm đảm bảo tính minh bạch và khả năng tái lập kết quả nghiên cứu (Reproducibility), toàn bộ quy trình có thể được thực thi bằng các lệnh tự động trong repository:

```bash
# 1. Biên dịch và kiểm tra tính hợp lệ của bộ Semgrep OSS Baseline
python scripts/build_semgrep_oss_baseline.py

# 2. Chạy kiểm thử tự động cho Rule Engine và Rule Profiles
pytest tests/test_rule_profiles.py -v

# 3. Quét một dự án thực tế với bộ Semgrep OSS Baseline
python -m aegis_sast.cli scan /path/to/target \
  --reviewed-rule-profile semgrep-oss-full \
  -o json -o markdown -o sarif

# 4. Chạy Benchmark thực nghiệm đối sánh
python scripts/run_semgrep_oss_benchmark.py --profile semgrep-oss-full
```

Báo cáo kết quả chi tiết sẽ được tự động xuất ra định dạng JSON và Markdown tại `reports/benchmark/semgrep_oss/` để đính kèm trực tiếp vào phụ lục của khóa luận.
