import tldextract
from urlextract import URLExtract
from config import settings

def check_phishing_heuristics(subject: str, body: str):
    score = 0
    reasons = []
    text = (subject or "") + "\n" + (body or "")
    text_lower = text.lower()
    extractor = URLExtract()
    urls = extractor.find_urls(text)

    for u in urls:
        root = f"{tldextract.extract(u).domain}.{tldextract.extract(u).suffix}"
        tld = tldextract.extract(u).suffix
        if u in settings.SUSPICIOUS_DOMAINS or root in settings.SUSPICIOUS_DOMAINS:
            score += 5
            reasons.append(f"Domínio suspeito: {u}")
        if tld in settings.SUSPICIOUS_TLDS:
            score += 1
            reasons.append(f"TLD suspeito: .{tld}")

    context_words = ["envie", "informe", "resgatar", "clique", "confirme", "forneça"]
    for word in settings.SENSITIVE_KEYWORDS:
        if word.lower() in text_lower and any(cw in text_lower for cw in context_words):
            score += 5
            reasons.append(f"Solicita dados: '{word}'")

    urgency = ["pague agora", "bloqueio da conta", "verifique sua conta", "senha expirada"]
    if any(u in text_lower for u in urgency):
        score += 3
        reasons.append("Mensagem urgente ou de bloqueio")

    return score, reasons
