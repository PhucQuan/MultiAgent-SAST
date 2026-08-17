# Roadmap thesis-safe tu vendor patterns cho Aegis-SAST V1

## 1. Muc dich

File nay quy doi cac pattern hoc duoc tu Datadog, Augment, va huong product AI-SAST thanh mot roadmap an toan cho thesis cua Aegis.

Muc tieu:

- chot Aegis nen hoc dieu gi truoc;
- chot pattern nao hop voi hien trang repo;
- tach ro current implementation, engineering gaps, research contribution, va demo value.

## 2. Ket luan ngan

Aegis V1 nen dinh vi la:

`Hybrid / AI-assisted SAST co orchestration seed`

Noi ngan gon:

- deterministic scanner la detector chinh;
- AI la lop triage / explanation / prioritization / remediation draft;
- workflow agent nam sau finding normalization, khong thay detector;
- AI-native detection chi nen la lane nghien cuu phu, khong phai lane chinh.

## 3. Pattern nen hoc truoc

## 3.1. AI triage la bai toan classification

Aegis nen chot Auditor / Skeptic / Judge thanh mot contract ro hon, vi du:

- `status`
- `confidence`
- `reason_codes`
- `evidence_summary`
- `manual_review_required`
- `reviewer`

Day la buoc rat hop voi hien trang repo, vi Aegis da co triage workflow seed roi.

## 3.2. Curated scope thay vi om tat ca CWE

V1 nen uu tien cac family da co evidence tot:

- `COMMAND_INJECTION`
- `PATH_TRAVERSAL`
- `INSECURE_DESERIALIZATION`

Mo rong sau:

- `SQL_INJECTION`
- `SSRF`

Can noi ro trong thesis:

`AI triage V1 chi benchmark tren curated family da co rule coverage va evidence coverage sach.`

## 3.3. Triage memory / review memory

Day la pattern nen hoc som nhat sau contract.

Can co cho:

- suppression memory;
- reviewer notes;
- approved false-positive patterns;
- historical fix notes;
- reviewed bundle provenance.

Huong nay rat hop voi Aegis vi repo da co:

- knowledge cards;
- reviewed bundles;
- local dashboard seed.

## 3.4. Scan khong chi nam trong CLI

Buoc productization hop ly la:

1. local dashboard doc report that;
2. diff-aware PR scan;
3. full scan on demand;
4. validator pass thu hai truoc khi post finding noi bat.

Khong nen nhay thang vao event bus hay platform lifecycle lon.

## 3.5. Chi highlight finding da duoc validate du manh

Pattern hop ly:

- detector sinh finding;
- triage danh gia;
- `confirmed` va `likely` dua len lane dashboard/PR;
- `needs-review` giu trong report day du;
- `suppressed` chi hien khi can xem low-confidence lane.

Day giup Aegis giong mot security workflow that su hon la mot list finding tho.

## 3.6. Remediation phai co rescan

Neu Aegis them remediation draft hoac fix suggestion, thi phai co:

- rescan lai dung file/path/family;
- so sanh before / after;
- chi sau do moi duoc goi la `resolved`.

Neu khong co validation loop, remediation de tro thanh demo dep nhung yeu.

## 3.7. Group finding theo root cause

Day la buoc sau, nhung rat hop voi huong Aegis:

- group theo family;
- group theo source pattern;
- group theo sink pattern;
- group theo root cause / shared code path;
- group theo provenance.

## 3.8. Orchestration co governance

V1 chi nen claim orchestration o muc:

- scan;
- normalize;
- triage;
- report;
- remediation draft.

Khong nen claim som:

- autonomous security platform;
- self-healing SDLC;
- AI agent toan quyen tren repo.

## 4. Current implementation

Aegis da co:

- scanner core;
- plugin da ngon ngu;
- Python graph core;
- rule governance seed;
- AI triage seed;
- JSON / Markdown / SARIF export;
- dashboard report-driven seed.

Day la nen du de lam V1 co gia tri hoc thuat va demo.

## 5. Engineering gaps

Can uu tien gap ky thuat theo thu tu:

1. triage contract chuan hoa;
2. triage memory / suppression memory;
3. report contract on dinh cho dashboard;
4. diff-aware PR scan;
5. remediation validation loop;
6. grouping / correlation layer.

## 6. Research contribution nen chot

Dong gop hop ly nhat cho Aegis V1:

1. evidence-first hybrid SAST + AI triage;
2. curated family benchmark cho false-positive filtering;
3. triage contract co confidence + explanation + route logic;
4. reviewed bundles / governance cho finding co provenance.

Day la nhung claim trung thuc hon va de bao ve hon so voi viec pitch Aegis nhu mot AI-native detector.

## 7. Demo value nen huong toi

Demo dep nhat cua Aegis V1 nen la:

1. scan repo / target;
2. workflow triage;
3. dashboard hien finding co confidence va evidence;
4. remediation draft;
5. rescan xac nhan.

Day la flow manh hon CLI thuan, nhung van nam trong scope thesis-safe.

## 8. Roadmap thesis-safe

## P0 - Contract va reviewer memory

- nang `TriageDecision`;
- them `reason_codes`;
- them `manual_review_required`;
- them reviewer memory / suppression memory;
- chot report schema cho dashboard va benchmark.

## P1 - Benchmark false-positive filtering

So sanh:

1. Aegis core
2. Aegis core + triage
3. Semgrep baseline

Metric uu tien:

- precision
- recall
- F1
- false-positive reduction
- manual-review rate

## P2 - Diff-aware PR scan + validator second pass

- changed-files mode;
- report gon cho PR;
- validator pass thu hai;
- chi highlight `confirmed` / `likely`.

## P3 - Remediation draft + rescan validation

- remediation note;
- patch draft co kiem soat;
- rerun scan sau sua;
- before / after summary.

## P4 - Grouping / correlation va orchestration sau hon

- group findings;
- correlate root causes;
- summary theo family / root cause / repo area;
- governance ro hon cho workflow.

## 9. Nhung gi chua nen uu tien ngay

Khong nen day som:

- AI-native detection lam lane chinh;
- claim LLM thay duoc dataflow / taint engine;
- event bus / platform lifecycle lon;
- pitch autonomous security agent qua som.

## 10. Cach viet vao khoa luan

Vendor patterns nen dung de:

- lay framing kien truc;
- lay product direction;
- doi chieu maturity model.

Bang chung thuc nghiem chinh van nen den tu:

- benchmark noi bo cua Aegis;
- OWASP Benchmark;
- Semgrep baseline;
- reviewed bundle benchmark;
- cac paper nhu QASecClaw va SAST-Genius.

## 11. Ket luan

Huong an toan nhat cho Aegis V1 la:

- giu scanner deterministic lam detector chinh;
- day manh triage contract va reviewer memory;
- dua dashboard/PR scan thanh product layer doc report;
- coi AI-native detection la lane nghien cuu phu.

Huong nay vua hop voi hien trang repo, vua de bao ve trong thesis, vua de product demo tron hon.
