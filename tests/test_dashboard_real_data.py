from pathlib import Path


def test_dashboard_uses_real_backend_data():
    html = Path(__file__).resolve().parents[1] / 'src' / 'templates' / 'dashboard_soc.html'
    text = html.read_text(encoding='utf-8')

    assert 'fetch("/data/agentes_status.json")' in text
    assert 'fetch("/data/roi_metrics.json")' in text
    assert 'fetch("/data/threat_intel.json")' in text
    assert 'Papa.parse("/data/vanguard_powerbi_data.csv"' in text
    assert '5 / 6' not in text
    assert '98.4%' not in text
