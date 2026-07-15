# Lo trinh nang cap Aegis-SAST cho Python, JavaScript va Java theo giai doan

## 1. Muc dich

Tai lieu nay chot thu tu nang cap thuc te cho Aegis-SAST theo huong da ngon ngu, trong do:

- Python khong phai ngon ngu duy nhat duoc dau tu.
- JavaScript va Java phai xuat hien o tat ca cac phase, khong bi day xuong cuoi roadmap.
- Do sau phan tich van duoc phan tang hop ly de khong vo scope do an.

Huong di tong quat la:

- hoc Semgrep o lop rule + AST + taint nhanh, phu rong nhieu ngon ngu
- hoc CodeQL o lop evidence, dataflow, path reasoning va benchmark
- giu Aegis-SAST la mot hybrid SAST co agent, khong bien thanh ban clone cua Semgrep hoac CodeQL

---

## 2. Nguyen tac thiet ke

### 2.1. Nguyen tac 1: Moi phase deu co gia tri cho ca 3 ngon ngu

Khong lam theo kieu:

- xong het Python roi moi den JavaScript
- xong het JavaScript roi moi den Java

Vi cach do lam demo rat lech, den luc bao ve se co cam giac project chi manh o 1 ngon ngu.

Thay vao do, moi phase deu phai tra loi duoc:

- Python tang gi?
- JavaScript tang gi?
- Java tang gi?

### 2.2. Nguyen tac 2: Rong truoc, sau do moi sau

Thu tu hop ly la:

1. chuan hoa schema va evidence cho ca 3 ngon ngu
2. nang dataflow cho ca 3 ngon ngu o muc co ich
3. tang do sau path reasoning o nhung diem co tac dong lon den false positive
4. dua agent vao sau khi evidence da du manh
5. benchmark va SARIF o cuoi de chung minh gia tri

### 2.3. Nguyen tac 3: Phan tang do sau

- Python: sau nhat, co the tien toi cross-file, DFG-lite va CFG-lite ro rang
- JavaScript: sau vua phai, tap trung Node.js/Express va call/assignment flow intra-file
- Java: sau vua phai, tap trung request -> service -> sink trong cung file hoac cung class, co mo hinh Spring/Servlet co ban

### 2.4. Nguyen tac 4: Dong bang scope PHP trong dot nay

PHP da co plugin, nhung neu muc tieu chinh cua dot nang cap nay la Python + JavaScript + Java thi nen dong bang PHP o muc:

- parse duoc
- detect duoc rule co ban
- khong nang cap sau trong dot nay

Nhu vay project se tap trung hon va de ra ket qua benchmark.

---

## 3. Hien trang hien tai cua 3 ngon ngu trong repo

### 3.1. Python

Dang la ngon ngu co nen tang tot nhat:

- AST parsing tot
- source/sink/sanitizer extraction da co
- taint propagation da co
- co `call_graph.py` va import resolution cho cross-file o muc ban dau

### 3.2. JavaScript

Da co:

- AST parsing
- source/sink/sanitizer extraction
- track dataflow intra-file co ban dua tren assignment va call usage

Chua co:

- model ro cho property flow
- model cho callback/promise route
- evidence bundle giau ngu canh
- CFG-lite cho early return/guard path

### 3.3. Java

Da co:

- AST parsing
- source/sink/sanitizer extraction
- taint propagation intra-method o muc co ban

Chua co:

- model method summary ro rang
- flow tot hon cho variable declaration, invocation chain, object member
- evidence phuc vu triage/benchmark
- path reasoning cho branch va try/catch

---

## 4. Roadmap 5 giai doan cho Python, JavaScript va Java

## Giai doan 1: AST + schema + evidence chung cho 3 ngon ngu

### Muc tieu

Dung mot schema thong nhat cho tat ca finding, de sau nay:

- agent co the triage bat ke finding den tu ngon ngu nao
- benchmark co the so sanh cong bang
- SARIF co the map on dinh

### Cong viec chung

- chuan hoa `NormalizedFinding`
- them `EvidenceBundle`
- bo sung `TriageStatus`
- dua `language`, `tool`, `rule_id`, `confidence`, `message`, `evidence` vao output
- cap nhat JSON exporter va Markdown exporter de hien evidence tot hon

### Cong viec theo ngon ngu

#### Python

- giu source, sink, sanitizer, intermediate steps theo schema moi
- map duoc cross-file evidence vao schema moi khi co

#### JavaScript

- dua source, sink, sanitizer va assignment path co ban vao `EvidenceBundle`
- bo sung nhan framework co ban: `express`, `koa`, `node:http` neu detect duoc

#### Java

- dua source, sink, sanitizer va invocation path co ban vao `EvidenceBundle`
- bo sung nhan framework co ban: `servlet`, `spring`, `jdbc`

### Dieu kien hoan thanh

- cung mot report JSON co the chua finding cua Python, JavaScript, Java voi schema giong nhau
- agent co the doc finding ma khong can biet plugin goc
- benchmark harness co the dem duoc finding theo ngon ngu, CWE, severity

### Gia tri demo

- nhin he thong da ra dang mot san pham da ngon ngu that su
- day la phase bat buoc truoc khi noi den agent

---

## Giai doan 2: DFG-lite v1 cho Python, JavaScript va Java

### Muc tieu

Tang chat luong luong du lieu, nhung chua lao vao graph engine hoc thuat day du.

Muc tieu cua phase nay la:

- giam false positive do match dong
- co `path summary` dep hon cho AI triage
- co du lieu thuyet phuc hon de benchmark

### Huong chung

Can bo sung 3 nhom flow:

- assignment flow: `a -> b`
- argument flow: `arg -> param`
- return flow: `return x -> y`

### Cong viec theo ngon ngu

#### Python

- giu assignment propagation hien co va nang len thanh intermediate steps ro rang
- ho tro `argument -> parameter` cho call trong cung file
- ho tro `return -> receiving variable`
- noi voi call graph hien co de cross-file path dep hon

#### JavaScript

- them flow cho:
  - `const a = req.query.id`
  - `let b = a`
  - `fn(b)`
  - `const x = helper(b)`
- uu tien Node.js/Express:
  - `req.query`, `req.body`, `req.params`
  - `res.send`, template render, child_process, fs path sinks
- bo sung member flow co ban:
  - `obj.userInput`
  - `req.body.name`

#### Java

- them flow cho:
  - local variable declaration
  - reassignment
  - `method(arg)` trong cung method va cung class
  - `String sql = input; stmt.execute(sql);`
- uu tien source/sink model cho:
  - `request.getParameter`
  - `@RequestParam`
  - JDBC execute/query
  - `Runtime.exec`
  - file/path API

### Dieu kien hoan thanh

- finding o ca 3 ngon ngu deu co intermediate steps co nghia
- AI triage co the doc duoc "data came from here -> moved here -> reached sink"
- precision tang so voi AST/rule-only tren sample set nho

### Gia tri demo

- day la phase giup project vuot qua muc pattern scanner don thuan
- luc nay project co the noi den `dataflow evidence`, khong chi `pattern match`

---

## Giai doan 3: CFG-lite v1 cho Python, JavaScript va Java

### Muc tieu

Khong xay full control-flow graph engine. Chi bo sung nhung gi tac dong truc tiep den false positive va triage quality.

### 3 nhom nang cap chinh

- branch-aware path
- sanitizer reachability
- early return / guard clause handling

### Cong viec theo ngon ngu

#### Python

- xu ly `if/else`
- xu ly `return` som
- xu ly `try/except` co ban
- kiem tra sanitizer co that su nam tren duong di toi sink hay khong

#### JavaScript

- xu ly `if/else`
- xu ly `return` som trong route handler
- xu ly guard clauses nhu:
  - `if (!input) return`
  - `if (isSafe(x)) return`
- phan biet path da validate va path chua validate

#### Java

- xu ly `if/else`
- xu ly `return` som
- xu ly `try/catch` co ban
- nhan dien path an toan khi dung API an toan hon, vi du prepared statement so voi string concat

### Dieu kien hoan thanh

- giam finding sai trong cac case co sanitizer/guard clause
- evidence hien duoc branch note don gian
- AI triage bat dau co co so tot hon de quyet dinh `suppressed` hay `confirmed`

### Gia tri demo

- day la phase giup project co mau "semantic" hon
- day cung la phase gan nhat voi phan cam hung tu CodeQL, nhung o muc vua du cho do an

---

## Giai doan 4: LangGraph workflow cho triage da ngon ngu

### Muc tieu

Luc nay moi dua agent vao, vi finding da co:

- schema thong nhat
- evidence bundle
- path summary tot hon
- thong tin sanitizer/branch co nghia

### Do thi de xuat

- `Planner/Router`
- `KnowledgeLoader`
- `Auditor`
- `SkepticValidator`
- `Judge`
- `Reporter`

### Cong viec theo ngon ngu

#### Python

- uu tien triage day du cho Python
- agent duoc phep doc them context file lien quan khi finding co cross-file path

#### JavaScript

- xay knowledge cards cho Express/Node.js:
  - source phan biet `req.query`, `req.body`, `req.params`
  - sink phan biet `child_process`, template render, file path, response output
- skeptic check:
  - validator middleware
  - escaping helper
  - route guard

#### Java

- xay knowledge cards cho Spring/Servlet/JDBC:
  - source `HttpServletRequest`, `@RequestParam`
  - sink JDBC execute, process exec, file API
  - safe API: prepared statement, whitelist validation
- skeptic check:
  - bean validation
  - custom sanitizer
  - safe builder API

### Dieu kien hoan thanh

- triage statuses chay duoc cho ca 3 ngon ngu:
  - `confirmed`
  - `likely`
  - `needs-review`
  - `suppressed`
- report co explanation va recommendation co phan biet theo ngon ngu

### Gia tri demo

- day la phase bien Aegis-SAST thanh `agentic hybrid SAST`
- luc nay slide va demo moi that su thuyet phuc

---

## Giai doan 5: SARIF + benchmark + baseline doi chieu

### Muc tieu

Chung minh gia tri khoa hoc va gia tri san pham.

### Cong viec chung

- xuat SARIF
- tich hop GitHub Actions hoac local CI script
- benchmark theo ngon ngu
- so sanh voi baseline

### Cach dung baseline

#### Semgrep

Dung lam baseline rong:

- Python
- JavaScript
- Java

So sanh cac chi so:

- tong so finding
- precision
- recall trong sample co nhan
- false positive reduction sau triage

#### CodeQL

Dung lam baseline sau hon o scope hep:

- uu tien 1-2 CWE cho Java va JavaScript
- hoac 1-2 CWE cho Python va Java
- khong nen om full matrix qua som

CodeQL nen duoc dung de doi chieu o nhung bai toan can dataflow/path reasoning manh, khong nhat thiet dung cho moi rule nho.

### Dataset de xuat

- Python: synthetic dataset + sample projects tu repo
- JavaScript: sample Node.js/Express apps tu nhom tu tao
- Java: sample Spring/Servlet mini apps va mot tap benchmark chon loc

### Dieu kien hoan thanh

- co bang so lieu rieng cho Python, JavaScript, Java
- co bang tong hop theo tung phase:
  - static core
  - core + DFG-lite
  - core + DFG-lite + CFG-lite
  - core + AI triage
- co bieu do so sanh voi Semgrep
- co 1 scope doi chieu voi CodeQL

### Gia tri demo

- day la phan giup de tai len muc nghien cuu
- neu khong co phase nay, project de bi xem la chi "co them AI"

---

## 5. Thu tu thuc thi trong thuc te

Neu lam theo thu tu coding thuc dung, nen di nhu sau:

1. Hoan thien schema + exporter cho ca 3 ngon ngu.
2. Bo sung evidence cho JavaScript va Java de bat kip Python.
3. Nang Python DFG-lite len muc dep va co path summary ro.
4. Nang JavaScript DFG-lite cho Express/Node.js.
5. Nang Java DFG-lite cho Servlet/Spring/JDBC.
6. Them CFG-lite cho Python truoc.
7. Them CFG-lite toi thieu cho JavaScript va Java.
8. Moi dua LangGraph triage vao.
9. Sau cung moi lam SARIF, benchmark, baseline doi chieu.

Thu tu nay tot hon cach lao vao agent som, vi:

- neu evidence con yeu thi agent chi doan
- neu schema chua on dinh thi benchmark se vo
- neu JS/Java chua co evidence thi demo da ngon ngu se rat mong

---

## 6. Phan cong theo phase cho Quan va Tue

## Giai doan 1

### Quan

- schema chung
- evidence bundle
- cap nhat detector va exporter
- dua Python, JavaScript, Java ve cung mot output

### Tue

- thiet ke triage status
- mock JSON cho agent
- knowledge schema chung theo CWE va ngon ngu

## Giai doan 2

### Quan

- DFG-lite Python
- DFG-lite JavaScript cho Express/Node.js
- DFG-lite Java cho Servlet/Spring/JDBC

### Tue

- xay knowledge cards theo language + CWE
- dinh dang prompt doc evidence bundle
- thiet ke rule de phan biet finding manh/yeu

## Giai doan 3

### Quan

- CFG-lite cho 3 ngon ngu
- uu tien sanitizer reachability va guard clause pruning

### Tue

- skeptic logic dua tren branch/sanitizer note
- dinh nghia khi nao suppressed, khi nao needs-review

## Giai doan 4

### Quan

- adapter tu scan result sang graph state
- language metadata, framework hints, source reader helper

### Tue

- LangGraph workflow
- router theo ngon ngu/CWE
- auditor, skeptic, judge, reporter

## Giai doan 5

### Quan

- SARIF
- benchmark harness
- Semgrep/CodeQL adapter hoac script doi chieu

### Tue

- ablation study
- danh gia AI triage
- tong hop bieu do va ket qua nghien cuu

---

## 7. Ket luan

Neu muon Aegis-SAST vua da ngon ngu, vua khong bi "chan" khi demo, thi dung la phai dua Python, JavaScript va Java vao cung roadmap. Tuy nhien, cach lam dung khong phai la dan trai deu moi thu cho 3 ngon ngu ngay lap tuc.

Huong hop ly nhat la:

- phase nao cung co deliverable cho Python, JavaScript, Java
- Python sau nhat
- JavaScript va Java duoc nang cap lien tuc o muc vua phai
- agent chi den sau khi 3 ngon ngu deu co evidence kha tot
- benchmark va SARIF den cuoi de chung minh gia tri

Neu lam dung thu tu nay, Aegis-SAST se khong con la mot scanner AST don gian, ma tro thanh mot de tai Agentic Hybrid SAST da ngon ngu co the bao ve tot va co kha nang mo rong that su.
