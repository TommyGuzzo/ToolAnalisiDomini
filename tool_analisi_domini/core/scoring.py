from typing import Dict, Any, Tuple

from .models import SectionResult


def _bounded(score: float, max_score: float) -> float:
    if score < 0:
        return 0.0
    if score > max_score:
        return max_score
    return score


def score_certificates_tls(data: Dict[str, Any]) -> SectionResult:
    max_score = 20.0
    score = 0.0

    if data.get("https_reachable"):
        score += 5.0
    if data.get("tls_version") in ("TLSv1.3", "TLSv1.2"):
        score += 5.0
    if data.get("certificate_valid"):
        score += 5.0
    if data.get("certificate_expires_in_days", 0) > 60:
        score += 3.0
    if data.get("has_chain_ok"):
        score += 2.0

    score = _bounded(score, max_score)
    status = "ok" if score >= 0.7 * max_score else "warning" if score >= 0.4 * max_score else "bad"
    return SectionResult(
        name="CERTIFICATES_TLS",
        score=score,
        max_score=max_score,
        status=status,
        details=data,
    )


def score_dns_security(data: Dict[str, Any]) -> SectionResult:
    max_score = 20.0
    score = 0.0
    if data.get("spf_valid"):
        score += 7.0
    if data.get("dmarc_valid"):
        score += 7.0
    if data.get("dkim_found"):
        score += 6.0
    score = _bounded(score, max_score)
    status = "ok" if score >= 0.7 * max_score else "warning" if score >= 0.4 * max_score else "bad"
    return SectionResult(
        name="DNS_SECURITY",
        score=score,
        max_score=max_score,
        status=status,
        details=data,
    )


def score_tech_detection(data: Dict[str, Any]) -> SectionResult:
    max_score = 10.0
    score = 5.0  # neutro
    risky = 0
    for tech in data.get("technologies", []):
        t = tech.lower()
        if "wordpress" in t or "joomla" in t or "drupal" in t:
            risky += 1
        if "php" in t:
            risky += 1
    score -= 2 * risky
    score = _bounded(score, max_score)
    status = "ok" if score >= 0.7 * max_score else "warning" if score >= 0.4 * max_score else "bad"
    return SectionResult(
        name="TECH_DETECTION",
        score=score,
        max_score=max_score,
        status=status,
        details=data,
    )


def score_shodan(data: Dict[str, Any]) -> SectionResult:
    max_score = 20.0
    score = max_score
    vulns = data.get("vulnerabilities", [])
    open_ports = data.get("open_ports", [])
    score -= 1.0 * min(len(open_ports), 10)
    score -= 2.0 * min(len(vulns), 10)
    score = _bounded(score, max_score)
    status = "ok" if score >= 0.7 * max_score else "warning" if score >= 0.4 * max_score else "bad"
    return SectionResult(
        name="SHODAN",
        score=score,
        max_score=max_score,
        status=status,
        details=data,
    )


def score_virustotal(data: Dict[str, Any]) -> SectionResult:
    max_score = 20.0
    score = max_score
    stats = data.get("last_analysis_stats") or {}
    malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
    score -= 3.0 * malicious
    score = _bounded(score, max_score)
    status = "ok" if score >= 0.7 * max_score else "warning" if score >= 0.4 * max_score else "bad"
    return SectionResult(
        name="VIRUSTOTAL",
        score=score,
        max_score=max_score,
        status=status,
        details=data,
    )


def score_bonus(data: Dict[str, Any]) -> SectionResult:
    max_score = 10.0
    score = 0.0
    if data.get("hsts"):
        score += 3.0
    if data.get("csp"):
        score += 3.0
    if data.get("x_frame_options"):
        score += 1.5
    if data.get("https_enforced"):
        score += 1.5
    if data.get("sri_coverage", 0) >= 0.5:
        score += 1.0
    score = _bounded(score, max_score)
    status = "ok" if score >= 0.7 * max_score else "warning" if score >= 0.4 * max_score else "bad"
    return SectionResult(
        name="BONUS_SECURITY_CHECKS",
        score=score,
        max_score=max_score,
        status=status,
        details=data,
    )


def overall_score_summary(sections: Dict[str, SectionResult]) -> Tuple[float, float]:
    total = sum(s.score for s in sections.values())
    max_total = sum(s.max_score for s in sections.values())
    return total, max_total