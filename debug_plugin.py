
import sys
from pathlib import Path
from aegis_sast.plugins.python_plugin import PythonPlugin
from aegis_sast.analysis.rule_engine import RuleEngine

def debug_plugin():
    plugin = PythonPlugin()
    file_path = Path('examples/vulnerable_sqli.py')
    rules_path = Path('rules/python.yaml')
    
    rule_engine = RuleEngine(rules_path)
    rules = rule_engine.get_rules()
    
    ast = plugin.parse_file(file_path)
    if not ast:
        print("Failed to parse file")
        return
        
    print("Extracting sources...")
    sources = plugin.extract_sources(ast, file_path, rules)
    for s in sources:
        print(f"Source: {s.pattern} at line {s.location.line_number}, var: {s.variable_name}")
        
    print("\nExtracting sinks...")
    sinks = plugin.extract_sinks(ast, file_path, rules)
    for s in sinks:
        print(f"Sink: {s.pattern} at line {s.location.line_number}, func: {s.function_name}")
        
    print("\nTracking dataflow...")
    all_paths = []
    for source in sources:
        paths = plugin.track_dataflow(ast, file_path, source, sinks, [])
        all_paths.extend(paths)
        
    print(f"\nFound {len(all_paths)} dataflow paths")
    for p in all_paths:
        print(f"Path: {p.source.pattern} -> {p.sink.pattern} (Line {p.source.location.line_number} -> {p.sink.location.line_number})")

if __name__ == "__main__":
    debug_plugin()
