# Python DFG/CFG Explicit Graph v1

## 1. Mục đích của tài liệu

Tài liệu này ghi lại bước nâng cấp quan trọng của Aegis-SAST từ cơ chế taint propagation heuristic sang hướng phân tích có đồ thị tường minh cho Python. Đây là bước nối giữa:

- scanner AST-based hiện có;
- nhu cầu giảm false positive bằng reasoning tốt hơn;
- định hướng khóa luận/NCKH cần có bằng chứng kỹ thuật rõ ràng.

## 2. Vấn đề của cách làm cũ

Trước khi bổ sung graph engine, `PythonPlugin.track_dataflow()` chủ yếu làm ba việc:

1. Dùng tập `tainted_vars` để lan truyền taint qua assignment.
2. Dùng heuristic kiểm tra call expression có chứa biến tainted hay không.
3. Dùng recursion đơn giản để kiểm tra imported helper có trả dữ liệu tainted không.

Cách này đủ cho demo ban đầu, nhưng có các hạn chế:

- chưa có CFG tường minh nên khó nói rõ reachability;
- chưa có DFG tường minh nên khó trình bày def-use chain;
- intermediate evidence còn nghèo;
- khó chứng minh với giảng viên rằng hệ thống đã có bước tiến về mặt static analysis.

## 3. Những gì đã được bổ sung

### 3.1. Module mới `aegis_sast/analysis/python_flow_graph.py`

Module này giới thiệu hai lớp chính:

- `PythonFlowGraphBuilder`: dựng explicit graph cho Python source code.
- `PythonDataflowAnalyzer`: truy vết taint path trên CFG/DFG đã dựng.

### 3.2. Cấu trúc đồ thị mới

Graph mới tách rõ:

- **Node**: assignment, call, branch, loop, return, function entry, parameter, merge.
- **CFG edges**: biểu diễn thứ tự thực thi, rẽ nhánh `true/false`, quay lại vòng lặp và merge.
- **DFG edges**: biểu diễn def-use giữa các biến đọc/ghi qua environment merge.

### 3.3. Những dạng Python statement đã được xử lý

Bản v1 đã có xử lý cho:

- `Assign`
- `AnnAssign`
- `AugAssign`
- `Expr(Call)`
- `If`
- `While`
- `For`
- `Return`
- `With`
- `FunctionDef`

Điểm quan trọng là `FunctionDef` không còn chỉ là cấu trúc cú pháp, mà đã có:

- `function_entry`
- `parameter nodes`
- body CFG riêng

### 3.4. Tích hợp vào Python plugin

`PythonPlugin.track_dataflow()` hiện đã chuyển sang:

1. dựng hoặc lấy từ cache `PythonFlowGraph`;
2. dùng `PythonDataflowAnalyzer` để trace path;
3. giữ lại cơ chế kiểm tra `callee return tainted` cho helper local/imported;
4. sinh `DataFlowPath.metadata` chứa:
   - `analysis_engine`
   - `graph_summary`
   - `cfg_path_node_ids`
   - `dfg_path_edges`

## 4. Giá trị kỹ thuật của bản v1

### 4.1. Về CFG

CFG hiện tại đã giúp giải quyết ít nhất một nhóm lỗi thực tế:

- path sau `return` không còn bị xem là reachable.

Điều này là một bước tiến rõ ràng so với cách duyệt AST cũ.

### 4.2. Về DFG

DFG hiện tại đã biểu diễn được:

- assignment propagation;
- data dependencies qua `reads` và `writes`;
- merge environment sau `if/else`;
- loop-carried environment ở mức thực dụng.

### 4.3. Về evidence

Finding hiện có thể mang thêm graph metadata đi xuyên qua:

- `Vulnerability`
- `NormalizedFinding`
- `EvidenceBundle`
- reporter
- SARIF/JSON consumer

Đây là điểm rất quan trọng cho phần benchmark và triage.

## 5. Những gì đã được cải thiện ngoài graph chính

Ngoài explicit graph engine, detector cũng đã được nới rộng thêm một bước:

- không chỉ synthesize source cho helper import từ file khác;
- mà còn bắt đầu synthesize source cho helper nằm cùng file nếu helper đó chứa source pattern.

Điều này giúp xử lý tốt hơn case:

- source nằm trong helper
- caller nhận dữ liệu qua giá trị trả về
- sink nằm ở caller

## 6. Giới hạn của bản v1

Mặc dù đã chuyển sang explicit graph, bản v1 vẫn chưa phải full graph engine học thuật hoàn chỉnh. Các giới hạn chính:

- chưa có SSA hoặc phi-node chính thức;
- chưa có inter-procedural CFG/DFG đầy đủ xuyên nhiều hàm theo graph chung;
- chưa xử lý sâu `try/except/finally`;
- chưa phân biệt semantic sanitizer effectiveness theo từng path;
- chưa có graph reasoning sâu cho JavaScript, Java, PHP.

Nói ngắn gọn:

> Đây là explicit Python CFG/DFG engine theo hướng thực dụng, đủ để nâng tầm đồ án và mở đường cho benchmark, nhưng chưa phải bản cuối cùng của hướng nghiên cứu.

## 7. Ý nghĩa đối với khóa luận và NCKH

Phần nâng cấp này làm mạnh đề tài ở ba chỗ:

1. **Có đóng góp kỹ thuật rõ ràng**:
   từ AST + heuristic sang explicit CFG/DFG cho Python.

2. **Có giá trị nghiên cứu đo được**:
   có thể làm ablation:
   - AST/Taint cũ
   - AST/Taint + explicit CFG/DFG

3. **Có giá trị trình bày học thuật**:
   khi viết báo cáo, nhóm có thể mô tả rõ:
   - node
   - edge
   - transfer function
   - path extraction
   - graph-aware evidence

## 8. Hướng nâng tiếp sau bản v1

### 8.1. Hướng nâng về CFG

- thêm `try/except/finally`
- thêm guard-clause reasoning sâu hơn
- thêm unreachable path pruning tốt hơn

### 8.2. Hướng nâng về DFG

- cải thiện return-value propagation giữa caller/callee
- thêm summary cho local helper functions
- tiến tới inter-procedural graph rõ hơn

### 8.3. Hướng nâng về benchmark

- đo Precision trước và sau khi có graph engine
- đo false-positive reduction trên synthetic dataset Python
- so sánh với Semgrep trên cùng tập dữ liệu

## 9. Kết luận

Việc bổ sung `python_flow_graph.py` là một bước nâng cấp thực chất của Aegis-SAST. Từ thời điểm này, repo không còn chỉ dựa vào propagation heuristic trong plugin Python nữa, mà đã có một nền explicit graph đủ rõ để:

- làm evidence tốt hơn;
- hỗ trợ triage tốt hơn;
- viết báo cáo đồ án/NCKH thuyết phục hơn;
- và làm nền cho benchmark nghiêm túc ở giai đoạn tiếp theo.
