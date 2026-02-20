import sys
from pathlib import Path
import yaml

from aegis_sast.plugins.python_plugin import PythonPlugin

def main():
    if len(sys.argv) < 2:
        print("Usage: python debug_plugin.py <file_to_scan>")
        return
        
    target_file = Path(sys.argv[1])
    
    # Load rules
    with open('rules/python.yaml', 'r') as f:
        rules = yaml.safe_load(f)
        
    plugin = PythonPlugin()
    
    print(f"Parsing: {target_file}")
    ast = plugin.parse_file(target_file)
    if not ast:
        print("Failed to parse AST")
        return
        
    print("AST Root:", ast.root_node.type)
    
    sources = plugin.extract_sources(ast, target_file, rules)
    print(f"\nFound {len(sources)} Sources:")
    for s in sources:
        print(f" - {s.source_type}: '{s.pattern}' -> Var '{s.variable_name}' at line {s.location.line_number}")
        
    sinks = plugin.extract_sinks(ast, target_file, rules)
    print(f"\nFound {len(sinks)} Sinks:")
    for s in sinks:
        print(f" - {s.sink_type.value}: {s.function_name} ('{s.pattern}') at line {s.location.line_number}")
        
    sanitizers = plugin.extract_sanitizers(ast, target_file, rules)
    print(f"\nFound {len(sanitizers)} Sanitizers.")
    
    print("\nTracking Dataflow...")
    all_paths = []
    for source in sources:
        paths = plugin.track_dataflow(ast, target_file, source, sinks, sanitizers, max_depth=10)
        all_paths.extend(paths)
        if paths:
            print(f"  Got {len(paths)} paths from source: {source}")
            for p in paths:
                print(f"    Path: Source(L{p.source.location.line_number}) -> Sink(L{p.sink.location.line_number})")
                
    print(f"\nTotal Confirmed Vulnerability Paths: {len(all_paths)}")

if __name__ == '__main__':
    main()
