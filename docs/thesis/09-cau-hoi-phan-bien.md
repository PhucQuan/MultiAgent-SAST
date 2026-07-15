# Cau hoi phan bien va khung tra loi

## 1. Vi sao em khong dung thang Semgrep hoac CodeQL?

Tra loi khung:

- Muc tieu cua de tai khong chi la su dung tool co san
- Em muon xay dung mot he thong co scanner core, AI triage, va kha nang agent hoa
- Em van dung Semgrep va CodeQL lam baseline de so sanh

## 2. Dong gop moi cua em la gi?

- xay dung scanner core AST + taint cho repo mau
- cross-file Python
- AI triage direction
- bo skill workflow de bien thanh SAST agent
- benchmark va so sanh de chung minh gia tri

## 3. AI co dang lam cho ket qua khong dang tin hon khong?

- AI khong thay deterministic evidence
- AI dung de xep hang, giai thich, va giam noise
- finding van giu source, sink, va dataflow evidence

## 4. Tai sao chi lam sau Python?

- De tai uu tien do sau hon do rong
- Python la ngon ngu duoc scanner hien tai ho tro sau nhat
- Cac ngon ngu khac van duoc giu o muc support co ban

## 5. Lam sao em danh gia do chinh xac?

- precision
- recall
- F1
- runtime
- false-positive reduction sau triage

## 6. He thong cua em co thay the duoc cong cu thuong mai khong?

- Khong
- Muc tieu la nghien cuu va xay dung mot he thong co gia tri hoc tap va thuc nghiem
- Em so sanh de tim vi tri cua he thong, khong tuyen bo thay the hoan toan

## 7. Tai sao can bo skill cho agent?

- de quy trinh hoa cong viec
- de agent lam dung thu tu
- de giam prompt thu cong va chuyen giao de dang

## 8. Vi sao can benchmark voi baseline?

- Neu khong benchmark thi rat kho bao ve dong gop
- Baseline giup dinh vi project trong he sinh thai SAST

## 9. Neu AI tra loi sai thi sao?

- Van giu evidence scanner
- Co status `needs-review`
- Khong suppress finding quan trong chi vi AI yeu

## 10. Neu hoi dong hoi san pham nay ung dung duoc o dau?

- trong mon hoc va phong thi nghiem AppSec
- trong CI noi bo o muc nghien cuu
- trong pipeline review cac sample project

