# Python Graph Ablation v1.2

Bo du lieu nay dung cho mini benchmark/ablation cua graph engine Python trong Aegis-SAST.

## Muc tieu

Bo case nay duoc thiet ke de do 3 lop nang cap:

- baseline taint tuyen tinh khong co CFG semantics;
- explicit CFG/DFG graph khong dung function summary;
- explicit CFG/DFG graph co function summary.

## Nhung gi duoc do

- flow truc tiep source -> sink
- safe overwrite / taint kill
- dead path sau `return`
- dead path sau `continue`
- local helper return-from-parameter
- local helper return-constant

## Cau truc

```text
python_graph_ablation_v1_2/
  manifest.json
  cases/
    001_direct_command_injection.py
    002_safe_reassignment.py
    003_return_dead_path.py
    004_continue_skips_sink.py
    005_helper_returns_parameter.py
    006_helper_returns_constant.py
```
