"""
Security Report Generator
Generates comprehensive JSON and HTML reports
FIXED: Added wrapper methods to match tool.py
"""

import json
from datetime import datetime
from jinja2 import Template


class ReportGenerator:
    def __init__(self, logger):
        self.logger = logger

    # ==================================================
    # WRAPPER METHODS (THIS IS THE KEY FIX)
    # ==================================================

    def generate_html_report(self, findings, attack_chains, filepath):
        """
        Wrapper used by tool.py
        Generates HTML report only
        """
        report = self._build_report(
            provider="AWS",
            findings=findings,
            attack_chains=attack_chains,
            remediations=[],
            risk_score=self._calculate_risk(findings)
        )
        self._generate_html_report(report, filepath)
        self.logger.success(f"HTML report saved: {filepath}")

    def generate_json_report(self, findings, filepath):
        """
        Wrapper used by tool.py
        Generates JSON report only
        """
        report = self._build_report(
            provider="AWS",
            findings=findings,
            attack_chains=[],
            remediations=[],
            risk_score=self._calculate_risk(findings)
        )
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)

        self.logger.success(f"JSON report saved: {filepath}")

    # ==================================================
    # INTERNAL REPORT BUILDER
    # ==================================================

    def _build_report(self, provider, findings, attack_chains, remediations, risk_score):
        return {
            "metadata": {
                "scan_date": datetime.now().isoformat(),
                "provider": provider,
                "tool": "Multi-Cloud Security Auditor",
                "version": "1.0.0"
            },
            "summary": {
                "total_findings": len(findings),
                "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
                "high": sum(1 for f in findings if f["severity"] == "HIGH"),
                "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
                "low": sum(1 for f in findings if f["severity"] == "LOW"),
                "risk_score": risk_score,
                "risk_level": self._get_risk_level(risk_score)
            },
            "findings": findings,
            "attack_chains": attack_chains,
            "remediations": remediations
        }

    def _calculate_risk(self, findings):
        score = 0
        for f in findings:
            if f["severity"] == "CRITICAL":
                score += 20
            elif f["severity"] == "HIGH":
                score += 10
            elif f["severity"] == "MEDIUM":
                score += 5
            elif f["severity"] == "LOW":
                score += 2
        return min(score, 100)

    def _get_risk_level(self, score):
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "MINIMAL"

    # ==================================================
    # HTML GENERATION (UNCHANGED CORE LOGIC)
    # ==================================================

    def _generate_html_report(self, report, filename):
        template = Template("""<!DOCTYPE html>
<html>
<head>
    <title>Cloud Security Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Arial, sans-serif; background: #f5f7fa; }
        .container { background: #fff; padding: 40px; max-width: 1400px; margin: 30px auto; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #232f3e; font-size: 32px; margin-bottom: 10px; }
        h2 { color: #232f3e; font-size: 24px; margin: 30px 0 15px; border-bottom: 3px solid #FF9900; padding-bottom: 8px; }
        .meta { color: #666; margin-bottom: 30px; }
        .summary { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 25px; border-radius: 8px; margin: 20px 0; }
        .summary h3 { margin-bottom: 15px; }
        .risk-badge { display: inline-block; padding: 8px 20px; border-radius: 20px; font-weight: bold; font-size: 18px; }
        .risk-CRITICAL { background: #e74c3c; }
        .risk-HIGH { background: #e67e22; }
        .risk-MEDIUM { background: #f39c12; }
        .risk-LOW { background: #3498db; }
        .risk-MINIMAL { background: #2ecc71; }
        .finding { background: #f8f9fa; padding: 20px; margin: 15px 0; border-left: 5px solid #ccc; border-radius: 5px; }
        .finding.CRITICAL { border-left-color: #e74c3c; }
        .finding.HIGH { border-left-color: #e67e22; }
        .finding.MEDIUM { border-left-color: #f39c12; }
        .finding.LOW { border-left-color: #3498db; }
        .severity { display: inline-block; padding: 4px 12px; border-radius: 4px; font-weight: bold; font-size: 12px; color: white; }
        .severity.CRITICAL { background: #e74c3c; }
        .severity.HIGH { background: #e67e22; }
        .severity.MEDIUM { background: #f39c12; }
        .severity.LOW { background: #3498db; }
        .attack-chain { background: #fff3cd; border: 2px solid #ffc107; padding: 20px; margin: 15px 0; border-radius: 8px; }
        .attack-chain h4 { color: #856404; margin-bottom: 10px; }
        .attack-steps { margin: 10px 0; padding-left: 20px; }
        .attack-step { padding: 8px 0; border-left: 3px solid #ffc107; padding-left: 15px; margin: 5px 0; }
        .mitre { display: inline-block; background: #17a2b8; color: white; padding: 3px 8px; border-radius: 3px; font-size: 11px; margin: 2px; }
        .disclaimer { background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .stats { display: flex; gap: 20px; margin: 15px 0; }
        .stat { flex: 1; text-align: center; }
        .stat-value { font-size: 32px; font-weight: bold; }
    </style>
</head>
<body>
<div class="container">
<h1>🔒 Cloud Security Assessment Report</h1>
<div class="meta">
    <p><b>Provider:</b> {{ report.metadata.provider }} | <b>Scan Date:</b> {{ report.metadata.scan_date }} | <b>Tool:</b> {{ report.metadata.tool }}</p>
</div>

<div class="summary">
    <h3>Executive Summary</h3>
    <p>Risk Score: <span class="risk-badge risk-{{ report.summary.risk_level }}">{{ report.summary.risk_score }}/100 - {{ report.summary.risk_level }}</span></p>
    <div class="stats">
        <div class="stat"><div class="stat-value">{{ report.summary.total_findings }}</div><div>Total Findings</div></div>
        <div class="stat"><div class="stat-value" style="color:#e74c3c;">{{ report.summary.critical }}</div><div>Critical</div></div>
        <div class="stat"><div class="stat-value" style="color:#e67e22;">{{ report.summary.high }}</div><div>High</div></div>
        <div class="stat"><div class="stat-value" style="color:#f39c12;">{{ report.summary.medium }}</div><div>Medium</div></div>
        <div class="stat"><div class="stat-value" style="color:#3498db;">{{ report.summary.low }}</div><div>Low</div></div>
    </div>
</div>

<h2>🔍 Security Findings</h2>
{% if report.findings %}
{% for f in report.findings %}
<div class="finding {{ f.severity }}">
    <span class="severity {{ f.severity }}">{{ f.severity }}</span>
    <h3 style="margin: 10px 0;">{{ f.description }}</h3>
    <p><b>Resource:</b> <code>{{ f.resource }}</code></p>
    {% if f.get('cwe') %}<p><b>CWE:</b> {{ f.cwe }}</p>{% endif %}
</div>
{% endfor %}
{% else %}
<p style="color: #2ecc71; font-size: 18px;">✓ No security findings detected. Your cloud environment appears secure!</p>
{% endif %}

<h2>⚠️ Attack Simulation Scenarios</h2>
<div class="disclaimer">
    <b>⚠️ Disclaimer:</b> All attack scenarios below are <b>logic-based simulations</b> for educational purposes. No actual exploitation or penetration testing was performed. These represent theoretical attack paths based on detected vulnerabilities.
</div>

{% if report.attack_chains %}
{% for attack in report.attack_chains %}
<div class="attack-chain">
    <h4>🎯 {{ attack.name }}</h4>
    <p><b>Severity:</b> <span class="severity {{ attack.severity }}">{{ attack.severity }}</span></p>
    <p><b>Description:</b> {{ attack.description }}</p>
    
    {% if attack.get('steps') %}
    <div class="attack-steps">
        <b>Attack Steps:</b>
        {% for step in attack.steps %}
        <div class="attack-step">{{ loop.index }}. {{ step }}</div>
        {% endfor %}
    </div>
    {% endif %}
    
    {% if attack.get('mitre_tactics') %}
    <p style="margin-top: 10px;"><b>MITRE ATT&CK:</b> 
    {% for tactic in attack.mitre_tactics %}
        <span class="mitre">{{ tactic }}</span>
    {% endfor %}
    </p>
    {% endif %}
</div>
{% endfor %}
{% else %}
<p style="color: #2ecc71; font-size: 18px;">✓ No attack scenarios generated. No exploitable vulnerability chains detected.</p>
{% endif %}

<div style="margin-top: 40px; padding-top: 20px; border-top: 2px solid #eee; color: #666; font-size: 12px;">
    <p>Generated by Multi-Cloud Security Auditor v{{ report.metadata.version }}</p>
    <p>This report is confidential and intended for authorized personnel only.</p>
</div>
</div>
</body>
</html>""")

        with open(filename, "w", encoding="utf-8") as f:
            f.write(template.render(report=report))
