# Kế Hoạch Thực Thi & Triển Khai Nâng Cấp Toàn Diện (Aegis-SAST)

> **Mã tài liệu:** `87-ke-hoach-thuc-thi-va-nang-cap-toan-dien.md`  
> **Ngày lập:** 09/10/2026  
> **Trạng thái:** Đang triển khai thực thi (In-Progress)  
> **Phạm vi:** 5 Pha nâng cấp từ Core Engine, API Persistence, Frontend Export, CI/CD đến Ablation Study Benchmark.

---

## 1. Mục Tiêu Tổng Thể

Chuyển đổi toàn diện các đề xuất từ tài liệu `86` thành mã nguồn và kịch bản thực tế, đảm bảo:
1. **Độ ổn định tuyệt đối của Core:** Triệt tiêu hoàn toàn lỗi root traversal leak làm treo scanner khi quét file đơn lẻ hoặc chạy kiểm thử.
2. **Khả năng lưu trữ và xuất báo cáo:** Backend lưu scan jobs bền vững xuống đĩa; hỗ trợ tải trực tiếp SARIF, Markdown và file Git Patch.
3. **Chuẩn hóa CI/CD DevSecOps:** Cung cấp workflow GitHub Actions mẫu sẵn sàng upload SARIF lên GitHub Security.
4. **Minh chứng học thuật vững chắc:** Cung cấp runner đo đạc Ablation Study 4 tầng đối đầu Semgrep OSS, chứng minh vai trò độc lập của từng khối kỹ thuật.

---

## 2. Kế Hoạch 5 Pha Chi Tiết

| Pha | Hạng mục | Tệp tin tác động | Kết quả nghiệm thu |
| :---: | :--- | :--- | :--- |
| **Pha 1** | **Vá lỗi Root Boundary Leak (P0)** | `aegis_sast/analysis/python_deep_analysis.py` | `pytest tests/test_taint_analysis.py` pass trong < 5 giây; không duyệt vượt quá `Path.home()` hoặc `tempfile`. |
| **Pha 2** | **Lưu trữ Scan Bền Vững & API Exporters (P1)** | `aegis_sast/api/routes.py` | Scan job lưu vào `reports/scans/<id>.json`; bổ sung endpoints xuất SARIF, Markdown, Patch `.diff`. |
| **Pha 3** | **Tích hợp Tải Báo Cáo trên Web Dashboard (P2)** | `apps/findings-dashboard/src/` | Nút Export SARIF, Download Patch trên giao diện web hoạt động 100%. |
| **Pha 4** | **CI/CD GitHub Action & Quality Gate (P3)** | `.github/workflows/aegis-scan.yml`, `aegis_sast/cli.py` | Workflow mẫu kích hoạt khi push/PR; cờ `--fail-on` chặn build khi có lỗ hổng nguy hiểm. |
| **Pha 5** | **Runner Ablation Study & Bảng Số Liệu (P4)** | `scripts/run_ablation_study.py` | Xuất bảng đo 4 cấu hình: Raw Semgrep -> Intra DFG -> Cross-file DFG -> Aegis Full. |

---

## 3. Nhật Ký Triển Khai

- **09/10/2026:** Khởi tạo kế hoạch, bắt đầu triển khai Pha 1 (Vá lỗi `_infer_project_root`).
