# INTEGRATION GUIDE - Next-Level Modules

## Files Created:
1. `src/attack_graph/path_analyzer.py` - Attack Path Graph
2. `src/baseline/drift_detector.py` - Baseline Drift Detection  
3. `src/risk_scoring/context_scorer.py` - Context-Aware Risk Scoring

## Changes Needed in tool.py:

### 1. Add imports (after line 17):
```python
from attack_graph.path_analyzer import AttackPathGraph
from baseline.drift_detector import BaselineDriftDetector
from risk_scoring.context_scorer import ContextAwareRiskScorer
```

### 2. Add instance variables in __init__ (after line 35):
```python
self.last_attack_graph = None
self.last_drift_report = None
self.last_risk_scores = None
```

### 3. In run_aws_scan(), replace lines 485-492 with:
```python
self.log("Running security checks...")
findings = scanner.run_scan()

# NEW: Attack Path Graph
self.log("Building attack path graph...")
graph_analyzer = AttackPathGraph()
self.last_attack_graph = graph_analyzer.build_graph(findings)
self.log(f"Found {self.last_attack_graph['total_paths']} attack paths")

# NEW: Baseline Drift Detection
self.log("Checking baseline drift...")
drift_detector = BaselineDriftDetector()
self.last_drift_report = drift_detector.detect_drift('aws', findings)
self.log(self.last_drift_report['summary'])

# NEW: Context-Aware Risk Scoring
self.log("Calculating risk scores...")
risk_scorer = ContextAwareRiskScorer()
self.last_risk_scores = risk_scorer.score_all_findings(findings, self.last_attack_graph)
self.log(f"Top risk score: {self.last_risk_scores[0]['risk_score']}")

# Existing attack simulator
simulator = AttackChainSimulator(SecurityLogger("attack.log"))
self.last_attack_chains = simulator.simulate_attacks(findings)
self.last_findings = findings
```

### 4. Add new UI tab (after line 240, before REPORT TAB):
```python
# ATTACK PATHS TAB
paths_tab = tk.Frame(notebook, bg="#0d1117")
notebook.add(paths_tab, text="🎯 Attack Paths")

paths_header = tk.Frame(paths_tab, bg="#161b22", height=50)
paths_header.pack(fill="x")
paths_header.pack_propagate(False)
tk.Label(
    paths_header, text="🎯 ATTACK PATH ANALYSIS (SIMULATED)",
    font=("Arial", 12, "bold"),
    bg="#161b22", fg="#58a6ff"
).pack(side="left", padx=15, pady=10)

self.paths_text = scrolledtext.ScrolledText(
    paths_tab,
    bg="#0d1117",
    fg="#ffc107",
    font=("Consolas", 9),
    insertbackground="white",
    relief="flat"
)
self.paths_text.pack(fill="both", expand=True, padx=15, pady=15)
self.paths_text.insert("1.0", "⏳ Run a scan to see attack path analysis")
self.paths_text.config(state="disabled")

# DRIFT TAB
drift_tab = tk.Frame(notebook, bg="#0d1117")
notebook.add(drift_tab, text="📊 Drift")

drift_header = tk.Frame(drift_tab, bg="#161b22", height=50)
drift_header.pack(fill="x")
drift_header.pack_propagate(False)
tk.Label(
    drift_header, text="📊 BASELINE DRIFT DETECTION",
    font=("Arial", 12, "bold"),
    bg="#161b22", fg="#58a6ff"
).pack(side="left", padx=15, pady=10)

self.drift_text = scrolledtext.ScrolledText(
    drift_tab,
    bg="#0d1117",
    fg="#58a6ff",
    font=("Consolas", 9),
    insertbackground="white",
    relief="flat"
)
self.drift_text.pack(fill="both", expand=True, padx=15, pady=15)
self.drift_text.insert("1.0", "⏳ Run a scan to see drift analysis")
self.drift_text.config(state="disabled")
```

### 5. Add update method (after update_metrics):
```python
def update_advanced_metrics(self):
    # Update Attack Paths
    if self.last_attack_graph:
        self.paths_text.config(state="normal")
        self.paths_text.delete("1.0", tk.END)
        
        graph_analyzer = AttackPathGraph()
        graph_analyzer.attack_paths = self.last_attack_graph['attack_paths']
        self.paths_text.insert("1.0", graph_analyzer.get_summary())
        
        self.paths_text.config(state="disabled")
    
    # Update Drift
    if self.last_drift_report:
        self.drift_text.config(state="normal")
        self.drift_text.delete("1.0", tk.END)
        self.drift_text.insert("1.0", self.last_drift_report['summary'])
        self.drift_text.config(state="disabled")
```

### 6. Call new update method (in run_aws_scan after line 498):
```python
self.root.after(0, self.update_metrics)
self.root.after(0, self.update_advanced_metrics)  # ADD THIS LINE
```

## Testing:
1. Run scan
2. Check "Attack Paths" tab - shows top 3 dangerous paths
3. Check "Drift" tab - shows changes since last scan
4. Run scan again - drift tab shows new/fixed issues

## Architecture Decisions:
- **Attack Graph**: Uses directed graph model, calculates risk per edge
- **Drift Detection**: Saves JSON baselines, compares by signature
- **Risk Scoring**: Multi-factor (severity + exposure + privilege + paths)
- **No Breaking Changes**: All modules are additive, existing code untouched
- **Explainable**: Every score has human-readable explanation
