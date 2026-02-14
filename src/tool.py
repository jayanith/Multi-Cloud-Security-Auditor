"""
Cloud Security Scanner - Professional Edition
Fixed version:
- Single log widget
- Real-time log streaming
- Reliable report download
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import os, sys, socket, tempfile, threading, time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.logger import SecurityLogger
from scanners.aws_scanner import AWSScanner
from attack_simulator.attack_chains import AttackChainSimulator
from attack_graph.path_analyzer import AttackPathGraph
from baseline.drift_detector import BaselineDriftDetector
from risk_scoring.context_scorer import ContextAwareRiskScorer

try:
    from scanners.gcp_scanner import GCPScanner
    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False


class ProfessionalCloudTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Cloud Security Scanner - Professional Edition")
        self.root.geometry("1400x900")
        self.root.minsize(1400, 900)
        self.root.configure(bg="#1a1a2e")

        self.credentials = {}
        self.credentials_configured = False

        self.last_findings = []
        self.last_attack_chains = []
        self.last_attack_paths = []
        self.last_drift_report = None
        
        self.drift_detector = BaselineDriftDetector()
        self.risk_scorer = ContextAwareRiskScorer()

        self.bg_dark = "#1a1a2e"
        self.bg_card = "#16213e"
        self.accent = "#0f3460"
        self.text_white = "#ffffff"
        self.text_gray = "#a0a0a0"
        self.aws_orange = "#FF9900"
        self.azure_blue = "#0078D4"
        self.gcp_blue = "#4285F4"

        self.create_ui()
        self.check_internet()

    # ---------------- STYLING ----------------
    
    def style_notebook_tabs(self):
        """
        Configure ttk.Notebook tab appearance.
        
        Why this is needed:
        - ttk.Notebook tabs are NOT regular Tkinter widgets
        - They ignore font, padding, and size parameters passed to notebook.add()
        - Must use ttk.Style to override TNotebook.Tab theme elements
        - This applies globally to all notebooks in the application
        """
        style = ttk.Style()
        
        # Set theme base (works cross-platform)
        try:
            style.theme_use('clam')  # Modern, customizable theme
        except:
            pass  # Fallback to default if clam unavailable
        
        # Configure TNotebook (the notebook container)
        style.configure('TNotebook', 
            background='#16213e',
            borderwidth=0
        )
        
        # Configure TNotebook.Tab (individual tab buttons)
        style.configure('TNotebook.Tab',
            background='#0f3460',      # Normal state background
            foreground='#a0a0a0',      # Normal state text color
            padding=[20, 12],          # [horizontal, vertical] padding
            font=('Arial', 11, 'bold'), # Tab font
            borderwidth=0
        )
        
        # Selected tab state
        style.map('TNotebook.Tab',
            background=[('selected', '#1a1a2e')],  # Active tab background
            foreground=[('selected', '#58a6ff')],  # Active tab text
            expand=[('selected', [1, 1, 1, 0])]    # Expand selected tab slightly
        )

    # ---------------- UI ----------------

    def create_ui(self):
        # Configure ttk.Notebook tab styling BEFORE creating notebook
        # ttk widgets ignore normal Tkinter sizing - they require ttk.Style configuration
        self.style_notebook_tabs()
        
        header = tk.Frame(self.root, bg=self.bg_dark)
        header.pack(fill="x", padx=30, pady=20)

        tk.Label(
            header, text="CLOUD SECURITY SCANNER",
            font=("Arial", 32, "bold"),
            bg=self.bg_dark, fg=self.text_white
        ).pack(anchor="w")

        tk.Label(
            header, text="Multi-Cloud Automated Pentesting & Security Auditor",
            font=("Arial", 14),
            bg=self.bg_dark, fg=self.text_gray
        ).pack(anchor="w")

        main = tk.Frame(self.root, bg=self.bg_dark)
        main.pack(fill="both", expand=True, padx=30, pady=15)

        # -------- LEFT PANEL --------
        left = tk.Frame(main, bg=self.bg_card, width=350)
        left.pack(side="left", fill="y", padx=(0, 15))
        left.pack_propagate(False)

        tk.Label(
            left, text="CLOUD PROVIDER",
            font=("Arial", 16, "bold"),
            bg=self.bg_card, fg=self.text_white
        ).pack(pady=25)

        self.provider_var = tk.StringVar(value="aws")

        for name, color in [("aws", self.aws_orange), ("azure", self.azure_blue), ("gcp", self.gcp_blue)]:
            btn = tk.Radiobutton(
                left, text=name.upper(),
                variable=self.provider_var, value=name,
                indicatoron=False,
                font=("Arial", 14, "bold"),
                bg=self.accent, fg="white",
                selectcolor=color,
                height=2,
                command=self.provider_changed
            )
            btn.pack(fill="x", padx=25, pady=8)

        tk.Button(
            left, text="CONFIGURE CREDENTIALS",
            command=self.open_credentials_modal,
            bg=self.accent, fg="white",
            font=("Arial", 13, "bold"),
            height=2
        ).pack(fill="x", padx=25, pady=20)

        self.config_status = tk.Label(
            left, text="Not Configured",
            font=("Arial", 11),
            bg=self.bg_card, fg="#ff4757"
        )
        self.config_status.pack()

        self.scan_btn = tk.Button(
            left, text="START SECURITY SCAN",
            bg="#00ff88", fg="#000",
            font=("Arial", 15, "bold"),
            height=2,
            state="disabled",
            command=self.start_scan
        )
        self.scan_btn.pack(fill="x", padx=25, pady=30)

        # -------- RIGHT PANEL --------
        right = tk.Frame(main, bg=self.bg_card)
        right.pack(side="right", fill="both", expand=True)

        notebook = ttk.Notebook(right)
        notebook.pack(fill="both", expand=True, padx=25, pady=25)

        # LOG TAB
        log_tab = tk.Frame(notebook, bg="#0d1117")
        notebook.add(log_tab, text="📋 Scan Logs")

        log_header = tk.Frame(log_tab, bg="#161b22", height=80)
        log_header.pack(fill="x")
        log_header.pack_propagate(False)

        tk.Label(
            log_header, text="🔍 REAL-TIME SCAN OUTPUT",
            font=("Arial", 16, "bold"),
            bg="#161b22", fg="#58a6ff"
        ).pack(side="left", padx=25, pady=20)

        self.status_label = tk.Label(
            log_header, text="● Ready",
            font=("Arial", 13, "bold"),
            bg="#161b22", fg="#00ff88"
        )
        self.status_label.pack(side="right", padx=25)

        log_container = tk.Frame(log_tab, bg="#0d1117")
        log_container.pack(fill="both", expand=True, padx=25, pady=25)

        self.log_text = scrolledtext.ScrolledText(
            log_container,
            bg="#0d1117",
            fg="#58a6ff",
            font=("Consolas", 12),
            insertbackground="white",
            relief="solid",
            borderwidth=2,
            wrap="word"
        )
        self.log_text.pack(fill="both", expand=True)

        # METRICS TAB
        metrics_tab = tk.Frame(notebook, bg="#0d1117")
        notebook.add(metrics_tab, text="📊 Metrics")

        # Header
        metrics_header = tk.Frame(metrics_tab, bg="#161b22", height=80)
        metrics_header.pack(fill="x")
        metrics_header.pack_propagate(False)
        tk.Label(
            metrics_header, text="📊 SECURITY METRICS DASHBOARD",
            font=("Arial", 16, "bold"),
            bg="#161b22", fg="#58a6ff"
        ).pack(side="left", padx=25, pady=20)

        metrics_content = tk.Frame(metrics_tab, bg="#0d1117")
        metrics_content.pack(fill="both", expand=True, padx=25, pady=25)

        # Severity Counts
        severity_frame = tk.Frame(metrics_content, bg="#0d1117")
        severity_frame.pack(fill="x", pady=(0, 25))

        tk.Label(
            severity_frame, text="🔒 VULNERABILITY SEVERITY",
            font=("Arial", 15, "bold"),
            bg="#0d1117", fg="white"
        ).pack(pady=(0, 25))

        counts_frame = tk.Frame(severity_frame, bg="#0d1117")
        counts_frame.pack()

        self.critical_label = self.create_metric_box(counts_frame, "CRITICAL", "0", "#e74c3c")
        self.high_label = self.create_metric_box(counts_frame, "HIGH", "0", "#e67e22")
        self.medium_label = self.create_metric_box(counts_frame, "MEDIUM", "0", "#f39c12")
        self.low_label = self.create_metric_box(counts_frame, "LOW", "0", "#3498db")

        # Divider
        tk.Frame(metrics_content, bg="#30363d", height=2).pack(fill="x", pady=25)

        # Attack Scenarios
        attack_frame = tk.Frame(metrics_content, bg="#0d1117")
        attack_frame.pack(fill="both", expand=True)

        tk.Label(
            attack_frame, text="⚠️ ATTACK SIMULATION SCENARIOS",
            font=("Arial", 15, "bold"),
            bg="#0d1117", fg="white"
        ).pack(pady=(0, 20))

        attack_container = tk.Frame(attack_frame, bg="#161b22", relief="solid", borderwidth=2)
        attack_container.pack(fill="both", expand=True)

        self.attack_text = scrolledtext.ScrolledText(
            attack_container,
            bg="#0d1117",
            fg="#ffc107",
            font=("Consolas", 12),
            insertbackground="white",
            relief="flat",
            borderwidth=0,
            wrap="word"
        )
        self.attack_text.pack(fill="both", expand=True, padx=3, pady=3)
        self.attack_text.insert("1.0", "⏳ No attack scenarios generated yet. Run a scan first.")
        self.attack_text.config(state="disabled")

        # REPORT TAB
        report_tab = tk.Frame(notebook, bg="#0d1117")
        notebook.add(report_tab, text="📥 Reports")

        # Header
        report_header = tk.Frame(report_tab, bg="#161b22", height=50)
        report_header.pack(fill="x")
        report_header.pack_propagate(False)
        tk.Label(
            report_header, text="📥 EXPORT SECURITY REPORTS",
            font=("Arial", 12, "bold"),
            bg="#161b22", fg="#58a6ff"
        ).pack(side="left", padx=15, pady=10)

        # Content
        report_content = tk.Frame(report_tab, bg="#0d1117")
        report_content.pack(fill="both", expand=True, padx=40, pady=30)

        tk.Label(
            report_content, text="📄 Generate comprehensive security reports",
            font=("Arial", 11),
            bg="#0d1117", fg="#8b949e"
        ).pack(pady=(0, 30))

        # HTML Report Card
        html_card = tk.Frame(report_content, bg="#161b22", relief="solid", borderwidth=1)
        html_card.pack(fill="x", pady=15)

        tk.Label(
            html_card, text="🌐 HTML Report",
            font=("Arial", 12, "bold"),
            bg="#161b22", fg="white"
        ).pack(anchor="w", padx=20, pady=(15, 5))

        tk.Label(
            html_card, text="Professional web-based report with charts and attack scenarios",
            font=("Arial", 9),
            bg="#161b22", fg="#8b949e"
        ).pack(anchor="w", padx=20, pady=(0, 10))

        self.report_btn = tk.Button(
            html_card, text="📥 DOWNLOAD HTML REPORT",
            state="disabled",
            bg="#238636", fg="white",
            font=("Arial", 11, "bold"),
            height=2,
            relief="flat",
            cursor="hand2",
            command=self.download_report
        )
        self.report_btn.pack(fill="x", padx=20, pady=(0, 15))

        # JSON Report Card
        json_card = tk.Frame(report_content, bg="#161b22", relief="solid", borderwidth=1)
        json_card.pack(fill="x", pady=15)

        tk.Label(
            json_card, text="📋 JSON Report",
            font=("Arial", 12, "bold"),
            bg="#161b22", fg="white"
        ).pack(anchor="w", padx=20, pady=(15, 5))

        tk.Label(
            json_card, text="Machine-readable format for integration with other tools",
            font=("Arial", 9),
            bg="#161b22", fg="#8b949e"
        ).pack(anchor="w", padx=20, pady=(0, 10))

        self.json_btn = tk.Button(
            json_card, text="📥 DOWNLOAD JSON REPORT",
            state="disabled",
            bg="#1f6feb", fg="white",
            font=("Arial", 11, "bold"),
            height=2,
            relief="flat",
            cursor="hand2",
            command=self.download_json_report
        )
        self.json_btn.pack(fill="x", padx=20, pady=(0, 15))

        # ATTACK PATHS TAB
        paths_tab = tk.Frame(notebook, bg="#0d1117")
        notebook.add(paths_tab, text="🎯 Attack Paths")

        paths_header = tk.Frame(paths_tab, bg="#161b22", height=80)
        paths_header.pack(fill="x")
        paths_header.pack_propagate(False)
        tk.Label(
            paths_header, text="🎯 ATTACK PATH ANALYSIS",
            font=("Arial", 16, "bold"),
            bg="#161b22", fg="#58a6ff"
        ).pack(side="left", padx=25, pady=20)

        paths_container = tk.Frame(paths_tab, bg="#0d1117")
        paths_container.pack(fill="both", expand=True, padx=25, pady=25)

        self.paths_text = scrolledtext.ScrolledText(
            paths_container,
            bg="#0d1117",
            fg="#ff6b6b",
            font=("Consolas", 12),
            insertbackground="white",
            relief="solid",
            borderwidth=2,
            wrap="word"
        )
        self.paths_text.pack(fill="both", expand=True)
        self.paths_text.insert("1.0", "⏳ No attack paths analyzed yet. Run a scan first.")
        self.paths_text.config(state="disabled")

        # DRIFT TAB
        drift_tab = tk.Frame(notebook, bg="#0d1117")
        notebook.add(drift_tab, text="📊 Drift")

        drift_header = tk.Frame(drift_tab, bg="#161b22", height=80)
        drift_header.pack(fill="x")
        drift_header.pack_propagate(False)
        tk.Label(
            drift_header, text="📊 BASELINE DRIFT DETECTION",
            font=("Arial", 16, "bold"),
            bg="#161b22", fg="#58a6ff"
        ).pack(side="left", padx=25, pady=20)

        drift_container = tk.Frame(drift_tab, bg="#0d1117")
        drift_container.pack(fill="both", expand=True, padx=25, pady=25)

        self.drift_text = scrolledtext.ScrolledText(
            drift_container,
            bg="#0d1117",
            fg="#a29bfe",
            font=("Consolas", 12),
            insertbackground="white",
            relief="solid",
            borderwidth=2,
            wrap="word"
        )
        self.drift_text.pack(fill="both", expand=True)
        self.drift_text.insert("1.0", "⏳ No drift analysis yet. Run a scan first.")
        self.drift_text.config(state="disabled")

        self.log("System initialized. Ready to scan.", "success")

    # ---------------- LOGGING ----------------

    def log(self, message, tag="info"):
        def write():
            self.log_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}\n")
            self.log_text.see(tk.END)
        self.root.after(0, write)

    def create_metric_box(self, parent, label, value, color):
        box = tk.Frame(parent, bg="#161b22", relief="solid", borderwidth=2)
        box.pack(side="left", padx=15)
        
        inner = tk.Frame(box, bg=color, width=170, height=130)
        inner.pack(padx=3, pady=3)
        inner.pack_propagate(False)
        
        val_label = tk.Label(
            inner, text=value,
            font=("Arial", 38, "bold"),
            bg=color, fg="white"
        )
        val_label.pack(expand=True, pady=(20, 0))
        
        tk.Label(
            inner, text=label,
            font=("Arial", 11, "bold"),
            bg=color, fg="white"
        ).pack(pady=(0, 20))
        
        return val_label

    def update_metrics(self):
        critical = sum(1 for f in self.last_findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in self.last_findings if f["severity"] == "HIGH")
        medium = sum(1 for f in self.last_findings if f["severity"] == "MEDIUM")
        low = sum(1 for f in self.last_findings if f["severity"] == "LOW")

        self.critical_label.config(text=str(critical))
        self.high_label.config(text=str(high))
        self.medium_label.config(text=str(medium))
        self.low_label.config(text=str(low))

        # Update attack scenarios
        self.attack_text.config(state="normal")
        self.attack_text.delete("1.0", tk.END)
        
        if self.last_attack_chains:
            for i, attack in enumerate(self.last_attack_chains, 1):
                self.attack_text.insert(tk.END, f"\n━━━ ATTACK CHAIN #{i} ━━━\n", "title")
                self.attack_text.insert(tk.END, f"🎯 {attack['name']}\n", "name")
                self.attack_text.insert(tk.END, f"⚠️  Severity: {attack['severity']}\n")
                self.attack_text.insert(tk.END, f"📝 {attack['description']}\n\n")
        else:
            self.attack_text.insert(tk.END, "✓ No attack scenarios detected. Environment appears secure.")
        
        self.attack_text.config(state="disabled")

        # Update attack paths
        self.paths_text.config(state="normal")
        self.paths_text.delete("1.0", tk.END)
        
        if self.last_attack_paths:
            for i, path in enumerate(self.last_attack_paths, 1):
                self.paths_text.insert(tk.END, f"\n━━━ ATTACK PATH #{i} ━━━\n")
                self.paths_text.insert(tk.END, f"🔥 Risk Score: {path['risk_score']:.1f}/10\n")
                self.paths_text.insert(tk.END, f"🛤️ Path: {path['path_summary']}\n")
                self.paths_text.insert(tk.END, f"📝 Impact: {path['impact']}\n\n")
        else:
            self.paths_text.insert(tk.END, "✓ No critical attack paths identified.")
        
        self.paths_text.config(state="disabled")

        # Update drift
        self.drift_text.config(state="normal")
        self.drift_text.delete("1.0", tk.END)
        
        if self.last_drift_report:
            new_count = len(self.last_drift_report.get('new_risks', []))
            fixed_count = len(self.last_drift_report.get('fixed_issues', []))
            worsened_count = len(self.last_drift_report.get('worsened', []))
            
            self.drift_text.insert(tk.END, f"\n╔═══════════════════════════════════════════════════════════╗\n")
            self.drift_text.insert(tk.END, f"║  DRIFT SUMMARY\n")
            self.drift_text.insert(tk.END, f"╚═══════════════════════════════════════════════════════════╝\n\n")
            self.drift_text.insert(tk.END, f"  🔴 NEW RISKS:        {new_count}\n")
            self.drift_text.insert(tk.END, f"  ✅ FIXED ISSUES:     {fixed_count}\n")
            self.drift_text.insert(tk.END, f"  🟠 WORSENED:         {worsened_count}\n\n\n")
            
            if self.last_drift_report.get('new_risks'):
                self.drift_text.insert(tk.END, "═════════════════════════════════════════════════════════════\n")
                self.drift_text.insert(tk.END, "🔴 NEW RISKS DETECTED\n")
                self.drift_text.insert(tk.END, "═════════════════════════════════════════════════════════════\n\n")
                for risk in self.last_drift_report['new_risks'][:5]:
                    self.drift_text.insert(tk.END, f"  • [{risk['severity']}] {risk.get('title', risk.get('resource', 'Unknown'))}\n")
                self.drift_text.insert(tk.END, "\n\n")
            
            if self.last_drift_report.get('fixed_issues'):
                self.drift_text.insert(tk.END, "═════════════════════════════════════════════════════════════\n")
                self.drift_text.insert(tk.END, "✅ FIXED ISSUES\n")
                self.drift_text.insert(tk.END, "═════════════════════════════════════════════════════════════\n\n")
                for fix in self.last_drift_report['fixed_issues'][:5]:
                    self.drift_text.insert(tk.END, f"  ✓ [{fix['severity']}] {fix.get('title', fix.get('resource', 'Unknown'))}\n")
                self.drift_text.insert(tk.END, "\n\n")
            
            if self.last_drift_report.get('worsened'):
                self.drift_text.insert(tk.END, "═════════════════════════════════════════════════════════════\n")
                self.drift_text.insert(tk.END, "🟠 WORSENED CONFIGURATIONS\n")
                self.drift_text.insert(tk.END, "═════════════════════════════════════════════════════════════\n\n")
                for item in self.last_drift_report['worsened']:
                    finding = item.get('finding', {})
                    self.drift_text.insert(tk.END, f"  ⚠️  {finding.get('resource', 'Unknown')}: {item['old_severity']} → {item['new_severity']}\n")
                self.drift_text.insert(tk.END, "\n")
        else:
            self.drift_text.insert(tk.END, "⏳ No drift analysis yet. Run a scan first.")
        
        self.drift_text.config(state="disabled")

    # ---------------- PROVIDER ----------------

    def provider_changed(self):
        provider = self.provider_var.get()
        if provider in self.credentials:
            self.config_status.config(text="✓ Configured", fg="#00ff88")
            self.scan_btn.config(state="normal")
        else:
            self.config_status.config(text="Not Configured", fg="#ff4757")
            self.scan_btn.config(state="disabled")

    # ---------------- CREDENTIALS ----------------

    def open_credentials_modal(self):
        modal = tk.Toplevel(self.root)
        modal.title("Configure Credentials")
        modal.geometry("450x400")
        modal.configure(bg=self.bg_card)
        modal.transient(self.root)
        modal.grab_set()

        provider = self.provider_var.get()
        provider_colors = {"aws": self.aws_orange, "azure": self.azure_blue, "gcp": self.gcp_blue}
        color = provider_colors.get(provider, self.accent)

        # Header
        header = tk.Frame(modal, bg=color, height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(
            header, text=f"{provider.upper()} CREDENTIALS",
            font=("Arial", 16, "bold"),
            bg=color, fg="white"
        ).pack(expand=True)

        # Form
        form = tk.Frame(modal, bg=self.bg_card)
        form.pack(fill="both", expand=True, padx=30, pady=20)

        entries = {}

        def add(label):
            tk.Label(
                form, text=label,
                font=("Arial", 10, "bold"),
                bg=self.bg_card, fg=self.text_white
            ).pack(anchor="w", pady=(10, 2))
            e = tk.Entry(
                form,
                show="*" if "Secret" in label or "Key" in label else "",
                font=("Arial", 11),
                bg=self.accent, fg="white",
                insertbackground="white",
                relief="flat"
            )
            e.pack(fill="x", ipady=8)
            return e

        if provider == "aws":
            entries["access_key"] = add("Access Key ID")
            entries["secret_key"] = add("Secret Access Key")
            entries["region"] = add("Region (e.g., us-east-1)")
        elif provider == "azure":
            entries["subscription_id"] = add("Subscription ID")
            entries["tenant_id"] = add("Tenant ID")
            tk.Label(
                form, text="Note: Requires 'az login' authentication",
                font=("Arial", 9, "italic"),
                bg=self.bg_card, fg="#8b949e"
            ).pack(pady=(10, 0))
        elif provider == "gcp":
            entries["project_id"] = add("Project ID")
            entries["service_account_json"] = add("Service Account JSON Path")
            tk.Label(
                form, text="Note: Path to service account JSON key file",
                font=("Arial", 9, "italic"),
                bg=self.bg_card, fg="#8b949e"
            ).pack(pady=(10, 0))

        def save():
            self.credentials[provider] = {k: v.get() for k, v in entries.items()}
            self.credentials_configured = True
            self.config_status.config(text="✓ Configured", fg="#00ff88")
            self.scan_btn.config(state="normal")
            modal.destroy()
            self.log(f"{provider.upper()} credentials saved", "success")

        tk.Button(
            modal, text="SAVE CREDENTIALS",
            command=save,
            bg=color, fg="white",
            font=("Arial", 12, "bold"),
            height=2,
            relief="flat",
            cursor="hand2"
        ).pack(fill="x", padx=30, pady=20)

    # ---------------- SCAN ----------------

    def start_scan(self):
        provider = self.provider_var.get()
        
        if provider == "aws":
            creds = self.credentials["aws"]
            threading.Thread(
                target=self.run_aws_scan,
                args=(creds["access_key"], creds["secret_key"], creds["region"]),
                daemon=True
            ).start()
        elif provider == "azure":
            creds = self.credentials["azure"]
            threading.Thread(
                target=self.run_azure_scan,
                args=(creds["subscription_id"], creds["tenant_id"]),
                daemon=True
            ).start()
        elif provider == "gcp":
            creds = self.credentials["gcp"]
            threading.Thread(
                target=self.run_gcp_scan,
                args=(creds["project_id"], creds["service_account_json"]),
                daemon=True
            ).start()

    def run_aws_scan(self, ak, sk, region):
        self.scan_btn.config(state="disabled")
        self.status_label.config(text="● Scanning...", fg="#ffa502")
        self.log_text.delete("1.0", tk.END)

        try:
            self.log("Authenticating with AWS...")
            # Pass credentials directly to scanner instead of using environment variables
            scanner = AWSScanner(SecurityLogger("scan.log"), region, access_key=ak, secret_key=sk)
            
            # Verify credentials before scanning
            if not scanner.verify_credentials():
                self.log("Authentication failed - Invalid AWS credentials", "error")
                self.status_label.config(text="● Auth Failed", fg="#ff4757")
                return
            
            self.log("Running security checks...")
            findings = scanner.run_scan()

            # Enhanced risk scoring
            self.log("Calculating context-aware risk scores...")
            findings = self.risk_scorer.score_all_findings(findings)

            # Attack simulation
            simulator = AttackChainSimulator(SecurityLogger("attack.log"))
            self.last_attack_chains = simulator.simulate_attacks(findings)
            
            # Attack path analysis
            self.log("Analyzing attack paths...")
            path_graph = AttackPathGraph()
            path_graph.build_graph(findings)
            self.last_attack_paths = path_graph.get_top_attack_paths()
            
            # Drift detection
            self.log("Detecting baseline drift...")
            self.last_drift_report = self.drift_detector.detect_drift('aws', findings)
            
            self.last_findings = findings

            self.log(f"Scan completed. Findings: {len(findings)}", "success")

            self.root.after(0, self.update_metrics)
            self.report_btn.config(state="normal")
            self.json_btn.config(state="normal")
            self.status_label.config(text="● Complete", fg="#00ff88")

        except Exception as e:
            error_msg = str(e)
            if "authentication" in error_msg.lower() or "credentials" in error_msg.lower():
                self.log(f"Authentication failed: {e}", "error")
                self.status_label.config(text="● Auth Failed", fg="#ff4757")
            else:
                self.log(f"Scan failed: {e}", "error")
                self.status_label.config(text="● Failed", fg="#ff4757")

        finally:
            self.scan_btn.config(state="normal")

    def run_azure_scan(self, subscription_id, tenant_id):
        self.scan_btn.config(state="disabled")
        self.status_label.config(text="● Scanning...", fg="#ffa502")
        self.log_text.delete("1.0", tk.END)

        try:
            os.environ["AZURE_SUBSCRIPTION_ID"] = subscription_id
            os.environ["AZURE_TENANT_ID"] = tenant_id

            self.log("Authenticating with Azure...")
            
            try:
                from scanners.azure_scanner import AzureScanner
                scanner = AzureScanner(SecurityLogger("scan.log"), subscription_id)
                self.log("Running security checks...")
                findings = scanner.run_scan()

                # Enhanced risk scoring
                self.log("Calculating context-aware risk scores...")
                findings = self.risk_scorer.score_all_findings(findings)

                # Attack simulation
                simulator = AttackChainSimulator(SecurityLogger("attack.log"))
                self.last_attack_chains = simulator.simulate_attacks(findings)
                
                # Attack path analysis
                self.log("Analyzing attack paths...")
                path_graph = AttackPathGraph()
                path_graph.build_graph(findings)
                self.last_attack_paths = path_graph.get_top_attack_paths()
                
                # Drift detection
                self.log("Detecting baseline drift...")
                self.last_drift_report = self.drift_detector.detect_drift('azure', findings)
                
                self.last_findings = findings

                self.log(f"Scan completed. Findings: {len(findings)}", "success")
                self.root.after(0, self.update_metrics)
                self.report_btn.config(state="normal")
                self.json_btn.config(state="normal")
                self.status_label.config(text="● Complete", fg="#00ff88")
            except ImportError:
                self.log("Azure SDK not installed. Run: pip install azure-identity azure-mgmt-storage azure-mgmt-network", "error")
                self.status_label.config(text="● Failed", fg="#ff4757")

        except Exception as e:
            self.log(f"Scan failed: {e}", "error")
            self.status_label.config(text="● Failed", fg="#ff4757")

        finally:
            self.scan_btn.config(state="normal")

    def run_gcp_scan(self, project_id, service_account_json):
        self.scan_btn.config(state="disabled")
        self.status_label.config(text="● Scanning...", fg="#ffa502")
        self.log_text.delete("1.0", tk.END)

        try:
            os.environ["GCP_PROJECT_ID"] = project_id
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = service_account_json

            self.log("Authenticating with GCP...")
            
            if GCP_AVAILABLE:
                scanner = GCPScanner(SecurityLogger("scan.log"), project_id)
                self.log("Running security checks...")
                findings = scanner.run_scan()

                # Enhanced risk scoring
                self.log("Calculating context-aware risk scores...")
                findings = self.risk_scorer.score_all_findings(findings)

                # Attack simulation
                simulator = AttackChainSimulator(SecurityLogger("attack.log"))
                self.last_attack_chains = simulator.simulate_attacks(findings)
                
                # Attack path analysis
                self.log("Analyzing attack paths...")
                path_graph = AttackPathGraph()
                path_graph.build_graph(findings)
                self.last_attack_paths = path_graph.get_top_attack_paths()
                
                # Drift detection
                self.log("Detecting baseline drift...")
                self.last_drift_report = self.drift_detector.detect_drift('gcp', findings)
                
                self.last_findings = findings

                self.log(f"Scan completed. Findings: {len(findings)}", "success")
                self.root.after(0, self.update_metrics)
                self.report_btn.config(state="normal")
                self.json_btn.config(state="normal")
                self.status_label.config(text="● Complete", fg="#00ff88")
            else:
                self.log("GCP SDK not installed. Run: pip install google-cloud-storage google-cloud-compute", "error")
                self.status_label.config(text="● Failed", fg="#ff4757")

        except Exception as e:
            self.log(f"Scan failed: {e}", "error")
            self.status_label.config(text="● Failed", fg="#ff4757")

        finally:
            self.scan_btn.config(state="normal")

    # ---------------- REPORTS ----------------

    def download_report(self):
        self.log("Download report button clicked", "info")

        if not self.last_findings:
            messagebox.showinfo("Info", "No findings to export")
            return

        path = filedialog.asksaveasfilename(defaultextension=".html")
        if not path:
            return

        from reporting.report_generator import ReportGenerator
        gen = ReportGenerator(SecurityLogger("report.log"))
        gen.generate_html_report(self.last_findings, self.last_attack_chains, path)

        messagebox.showinfo("Success", "HTML report saved")

    def download_json_report(self):
        self.log("Download JSON report button clicked", "info")

        if not self.last_findings:
            messagebox.showinfo("Info", "No findings to export")
            return

        path = filedialog.asksaveasfilename(defaultextension=".json")
        if not path:
            return

        from reporting.report_generator import ReportGenerator
        gen = ReportGenerator(SecurityLogger("report.log"))
        gen.generate_json_report(self.last_findings, path)

        messagebox.showinfo("Success", "JSON report saved")

    # ---------------- INTERNET ----------------

    def check_internet(self):
        def check():
            try:
                socket.create_connection(("8.8.8.8", 53), timeout=3)
            except:
                pass
            self.root.after(5000, check)
        threading.Thread(target=check, daemon=True).start()


if __name__ == "__main__":
    root = tk.Tk()
    ProfessionalCloudTool(root)
    root.mainloop()
