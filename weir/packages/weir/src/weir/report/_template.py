"""The report's single Jinja2 template, kept in its own module so
renderer.py stays readable. Self-contained (inline CSS, no external
assets) so the rendered HTML opens anywhere with no server (R7 anatomy)."""

from __future__ import annotations

REPORT_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>weir scan report - {{ scenario_name }}</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 60rem;
         color: #1a1a1a; background: #fafafa; }
  h1 { font-size: 1.4rem; }
  .gauge { background: #eef2f7; border-radius: 8px; padding: 1rem 1.25rem; margin-bottom: 1.5rem; }
  .gauge .headline { font-size: 1.1rem; font-weight: 600; }
  .remediation { margin-top: 0.5rem; font-size: 0.9rem; color: #444; }
  .green-screen { background: #eafaf0; border: 1px solid #b6e6c9; border-radius: 8px;
                  padding: 1.5rem; font-size: 1.05rem; }
  .finding { border: 1px solid #e6b6b6; background: #fdf2f2; border-radius: 8px;
             padding: 1rem 1.25rem; margin-bottom: 1rem; }
  .finding .sentence { font-size: 1.05rem; margin-bottom: 0.5rem; }
  .finding .rule-caption { font-size: 0.8rem; color: #888; margin-bottom: 0.75rem; }
  .witness { display: flex; flex-wrap: wrap; gap: 0.5rem; }
  .witness .step { border: 1px solid #ccc; border-radius: 6px; padding: 0.4rem 0.6rem;
                    font-size: 0.85rem; background: #fff; }
  .witness .step.highlight { border-color: #c0392b; background: #fff3f3; font-weight: 600; }
  .review-queue { border: 1px solid #ddd; border-radius: 8px; padding: 1rem 1.25rem;
                  background: #fbfbfb; margin-top: 1rem; }
  .review-queue h2 { font-size: 1rem; color: #666; margin-top: 0; }
  footer { margin-top: 2rem; font-size: 0.8rem; color: #777; }
</style>
</head>
<body>
<h1>weir scan - {{ scenario_name }}</h1>

<div class="gauge">
  <div class="headline">evidentiary coverage: {{ coverage_pct }}% - {{ steps_scanned }} steps
    scanned, {{ rules_evaluated }} rules evaluated, {{ arg_capture_pct }}% argument capture</div>
  {% if remediation_line %}
  <div class="remediation">{{ remediation_line }}</div>
  {% endif %}
</div>

{% if verdict_grade_findings %}
  {% for f in verdict_grade_findings %}
  <div class="finding">
    <div class="sentence">{{ f.sentence }}</div>
    {% if f.rule_caption %}
    <div class="rule-caption">{{ f.rule_caption }}</div>
    {% endif %}
    <div class="witness">
      {% for step in f.witness_steps %}
      <div class="step{% if step.highlighted %} highlight{% endif %}">
        #{{ step.index }} {{ step.summary }}
      </div>
      {% endfor %}
    </div>
  </div>
  {% endfor %}
{% else %}
  <div class="green-screen">
    0 verdict-grade findings - {{ steps_scanned }} steps scanned, {{ rules_evaluated }} rules
    evaluated, {{ arg_capture_pct }}% argument capture
  </div>
{% endif %}

{% if review_queue %}
<div class="review-queue">
  <h2>review queue - context-mode, never a headline count</h2>
  {% for f in review_queue %}
  <div>{{ f.sentence }}</div>
  {% endfor %}
</div>
{% endif %}

<footer>{{ steps_scanned }} steps scanned, {{ rules_evaluated }} rules evaluated,
  {{ arg_capture_pct }}% argument capture.</footer>
</body>
</html>
"""
