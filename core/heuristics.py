import tldextract
from urlextract import URLExtract
from config.settings import SUSPICIOUS_TLDS, SUSPICIOUS_DOMAINS, SENSITIVE_KEYWORDS

def check_phishing_heuristics(subject: str, body: str):
    score = 0
    reasons = []

    text = (subject or "") + "\n" + (body or "")
    text_lower = text.lower()
    extractor = URLExtract()
    urls = extractor.find_urls(text)

    for u in urls:
        parsed = tldextract.extract(u)
        root = parsed.domain + ('.' + parsed.suffix if parsed.suffix else '')
        tld = parsed.suffix
        if u in SUSPICIOUS_DOMAINS or root in SUSPICIOUS_DOMAINS:
            score += 5
            reasons.append(f"Domínio suspeito: {u}")
        if tld in SUSPICIOUS_TLDS:
            score += 1
            reasons.append(f"TLD suspeito: .{tld}")

    context_words = ["envie", "informe", "resgatar", "clique", "confirme", "forneça"]
    for word in SENSITIVE_KEYWORDS:
        if word.lower() in text_lower and any(cw in text_lower for cw in context_words):
            score += 5
            reasons.append(f"Solicita dados pessoais: '{word}'")

    urgency_words = ["pague agora","bloqueio da conta","verifique sua conta","senha expirada"]
    if any(word in text_lower for word in urgency_words):
        score += 3
        reasons.append("Mensagem com urgência ou pagamento imediato.")

    return score, reasons