# Rule Review V1 synthetic assets

Thu muc nay chua bo seed input nho de test flow:

- `Semgrep-shaped seed`
- `normalized rule import`
- `validation`
- `legacy bridge export`
- `scan thu nghiem voi --rules`

V1 hien tai tap trung vao:

- `python`
- `COMMAND_INJECTION`
- `PATH_TRAVERSAL`
- `INSECURE_DESERIALIZATION`

Seed `python_command_injection_semgrep_shape.yaml` chu y cover cac sink command injection pho bien trong repo demo:

- `os.system(...)`
- `os.popen(...)`
- `subprocess.run(..., shell=True, ...)`
- `subprocess.call(..., shell=True, ...)`
- `subprocess.Popen(..., shell=True, ...)`

Day la fixture local de review flow, khong phai raw Semgrep registry snapshot.

Seed `python_path_traversal_semgrep_shape.yaml` chu y cover reviewed sinks gan voi file access that hon:

- `send_file(...)`
- `open(...)`
- `os.remove(...)`
- `os.listdir(...)`

No co chu y bo qua mot so path-construction calls qua rong nhu `os.path.join(...)` de flow review bundle tap trung hon vao sink truy cap tep that su.

Seed `python_insecure_deserialization_semgrep_shape.yaml` cover reviewed deserialization sinks cho Python:

- `pickle.loads(...)`
- `yaml.unsafe_load(...)`
- `yaml.load(...)`

Va co them `yaml.safe_load(...)` nhu mot reviewed sanitizer de flow compare co the tach ro safe-vs-unsafe loader.

Seed `python_sql_injection_semgrep_shape.yaml` la family mo rong sau 3 family V1 goc:

- `execute(...)`
- `executemany(...)`
- `raw(...)`

Fixture nay dung suffix-style callable patterns thay vi pattern mo rong kieu `.execute(` de reviewed flow tap trung hon vao execute-family sinks.
