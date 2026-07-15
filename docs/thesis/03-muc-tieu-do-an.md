# Muc tieu do an

## Ten de tai goi y

### Lua chon 1

`Aegis-SAST: He thong Agentic Hybrid SAST da ngon ngu ket hop AST Taint Analysis, AI Triage va Benchmark`

### Lua chon 2

`Xay dung tac tuan tri tue nhan tao ho tro phan tich bao mat ma nguon tinh cho nhieu ngon ngu lap trinh`

## Bai toan can chot

Thay vi noi "em lam mot SAST tool", nen chot bai toan manh hon:

`Xay dung mot he thong SAST Agent co kha nang quet, phan loai, giam false positive, de xuat sua loi, va tao bao cao co the dung cho quy trinh phat trien phan mem.`

## Muc tieu ky thuat

1. Giu vung scanner core hien tai.
2. Them bo skill orchestration cho agent.
3. Them normalized finding schema va triage workflow.
4. Co benchmark voi it nhat 1 den 2 baseline.
5. Them luong bao cao phu hop voi do an va demo.

## Muc tieu nghien cuu

1. Danh gia tac dong cua AI triage len false positives.
2. Danh gia gia tri cua cross-file analysis tren ngon ngu duoc ho tro sau nhat.
3. Danh gia kha nang chuan hoa finding tren he thong da ngon ngu.
4. So sanh Aegis-SAST voi baseline rule-based va query-based.

## Pham vi nen lam

### Nen lam sau

- Python la ngon ngu phan tich sau va benchmark chinh
- JavaScript, Java, PHP la ngon ngu mo rong de chung minh tinh da ngon ngu
- SQL Injection
- Command Injection
- Path Traversal
- XSS hoac SSRF

### Khong nen tham qua

- Ho tro qua nhieu ngon ngu sau cung luc
- Dua C++ vao phase dau khi chua co plugin, rules va test
- Lam dashboard lon neu chua co benchmark
- Hua full autofix neu chua co triage on dinh

## Tieu chi thanh cong

| Tieu chi | Muc tieu |
|---|---|
| Scanner core | Hoat dong on tren examples va projects mau |
| Agent workflow | Co skill pack va orchestration ro rang |
| Triage | Co schema va ket qua co `confirmed`/`likely`/`needs review` |
| Benchmark | Co so lieu so sanh voi baseline |
| Demo | Co luong scan -> triage -> remediation note -> report |
| Bao cao | Co tai lieu ky thuat va dong gop ro rang |
