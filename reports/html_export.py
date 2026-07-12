"""
Export to HTML
"""
from typing import Dict, Any
import os

def export_html(report: Dict[str, Any], output_path: str = "report.html") -> None:
    """
    Exports a simple HTML version of the report.
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    
    html_content = [
        "<html><head><title>SBOM Risk Report</title>",
        "<style>",
        "body { font-family: Arial, sans-serif; margin: 40px; }",
        "h1 { color: #333; }",
        "h2 { color: #555; border-bottom: 1px solid #ccc; padding-bottom: 5px; }",
        ".app-block { margin-bottom: 40px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }",
        "</style></head><body>",
        "<h1>SBOM Organization Risk Report</h1>"
    ]
    
    # Executive Summary
    summary = report.get("Executive Summary", {})
    html_content.append("<h2>Executive Summary</h2><ul>")
    for k, v in summary.items():
        html_content.append(f"<li><strong>{k}:</strong> {v}</li>")
    html_content.append("</ul>")
    
    # Priority
    priorities = report.get("Remediation Priority", [])
    html_content.append("<h2>Remediation Priority</h2><ol>")
    for p in priorities:
        html_content.append(f"<li>{p['Application']} (Rank: {p['Rank']}, Priority: {p['Priority']}) - {p['Reason']}</li>")
    html_content.append("</ol>")
    
    # Apps
    apps = report.get("Applications", [])
    for app in apps:
        info = app.get("Application Information", {})
        risk = app.get("Risk Information", {})
        html_content.append(f"<div class='app-block'><h2>{info.get('Name', 'Unknown App')}</h2>")
        html_content.append(f"<p><strong>Owner:</strong> {info.get('Owner', 'Unknown')}</p>")
        html_content.append(f"<p><strong>Risk Score:</strong> {risk.get('Overall Risk Score')} ({risk.get('Risk Category')})</p>")
        
        remediation = app.get("AI Remediation Plan", {})
        immed = remediation.get("Immediate Actions", [])
        if immed:
            html_content.append("<h3>Immediate Actions</h3><ul>")
            for action in immed:
                html_content.append(f"<li>{action['What']} - {action['How']} (Priority: {action['Priority']})</li>")
            html_content.append("</ul>")
            
        html_content.append("</div>")

    html_content.append("</body></html>")
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(html_content))
    print(f"HTML Report successfully exported to {output_path}")
