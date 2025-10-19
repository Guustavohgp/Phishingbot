#heuristics
import re
import logging
from types import SimpleNamespace
from urlextract import URLExtract
import tldextract
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Tenta importar settings do projeto; se não existir, settings será None
try:
    import settings
except Exception:
    settings = None

# Valores padrão 
DEFAULT_CONFIG = SimpleNamespace(
    SUSPICIOUS_DOMAINS=set([
        "malicious.com", "phish.example", "regularizarcnh", "gov-br.site", "govbr-login.com",
        "govbrseguro.com", "br-gov.net", "brgov.app", "brgovseguro.com", "cnhregulariza.com",
        "cnhdigitalbrasil.net", "receita-federal.online", "itau-verifica.com", "bbseguro.click",
        "caixalogin.net", "sistemagov.com", "govbr-autenticacao.com", "pixseguro.com", "meupix.app",
        "recuperarconta.net", "multastransito.click", "suporte-banco.com", "meupagamento.info",
        "pagamentosseguro.online", "pixverifica.net", "loginpixbr.com"
    ]),

    SUSPICIOUS_TLDS=set([
        "xyz", "top", "club", "loan", "click", "online", "shop", "store", "info", "live", "site",
        "fun", "buzz", "monster", "space", "tk", "ml", "ga", "gq", "cf", "pw", "cam", "work", "zip",
        "mov", "rest", "country", "biz", "pro", "app", "icu", "cyou", "press", "review"
    ]),

    SENSITIVE_KEYWORDS=set([
        "cpf", "senha", "cartão", "cartao", "pix", "dados", "informações", "informacao", "conta",
        "banco", "acesso", "token", "segurança", "codigo", "verificação", "confirmacao", "2fa",
        "autenticacao", "login", "credenciais", "transferência", "transacao", "pagamento",
        "chave", "saldo", "limite", "bloqueio", "extrato", "validação", "validar", "recuperar senha",
        "verificar", "atualizar dados", "autenticar", "documento", "comprovante"
    ]),

    SHORTENERS=set([
        "bit.ly", "tinyurl.com", "is.gd", "t.co", "ow.ly", "buff.ly", "cutt.ly", "shorturl.at",
        "rebrand.ly", "shorte.st", "soo.gd", "adf.ly", "ulvis.net", "v.gd", "lnkd.in", "qr.ae",
        "tiny.cc", "rb.gy", "trib.al", "1drv.ms", "goo.gl"
    ]),

    SUSPICIOUS_BRAND_WORDS=set([
        "cnh", "detran", "receita", "banco", "itau", "bradesco", "santander", "bb", "caixa", "gov",
        "govbr", "pix", "pagbank", "mercadopago", "mercadolivre", "nubank", "inter", "original",
        "sicoob", "sicredi", "neon", "trigg", "ame", "celcoin", "picpay", "paypal", "pagseguro",
        "serasa", "spc", "celular", "portabilidade", "seguro", "pagamento", "boleto", "cobranca",
        "regularizar", "multas", "renovar", "ipva", "licenciamento", "suspensao", "bloqueio",
        "recuperar", "restituicao", "nota fiscal"
    ]),

    URGENCY_PATTERNS=[
        "pague agora", "pague agora mesmo", "regularizar cnh", "bloqueada", "bloqueio",
        "para desbloquear", "pendente", "expirada", "ultima chance", "última chance",
        "link abaixo", "imediatamente", "urgente", "multas", "tempo limite", "tempo limite:",
        "evite suspensão", "seu acesso será bloqueado", "evite bloqueio", "regularize hoje",
        "evite multa", "atualize antes do prazo", "prazo final", "expira em", "último aviso",
        "encerramento", "seu cadastro expirou", "renove já", "urgente: ação necessária",
        "evite cancelamento", "não perca o prazo", "confirme imediatamente", "prazo termina hoje"
    ],

    CONTEXT_WORDS=[
        "envie", "informe", "confirme", "forneça", "forneca", "atualize", "verifique",
        "acesse", "clique", "autorize", "entre no link", "faça login", "acesse sua conta",
        "clique no botão", "envie seus dados", "preencha o formulário", "siga o link",
        "acesse o site", "resolva agora", "regularize aqui", "verifique seus dados",
        "valide suas informações", "recupere sua conta", "baixe o aplicativo", "acesse com segurança"
    ],

    DEFAULT_THRESHOLDS=SimpleNamespace(
        QUARANTINE_SCORE=6,
        SUSPECT_SCORE=3
    ),
)

# Load config
def _get_config():
    if settings is None:
        return DEFAULT_CONFIG
    cfg = SimpleNamespace()
    cfg.SUSPICIOUS_DOMAINS = set(getattr(settings, "SUSPICIOUS_DOMAINS", DEFAULT_CONFIG.SUSPICIOUS_DOMAINS))
    cfg.SUSPICIOUS_TLDS = set(getattr(settings, "SUSPICIOUS_TLDS", DEFAULT_CONFIG.SUSPICIOUS_TLDS))
    cfg.SENSITIVE_KEYWORDS = set(getattr(settings, "SENSITIVE_KEYWORDS", DEFAULT_CONFIG.SENSITIVE_KEYWORDS))
    cfg.SHORTENERS = set(getattr(settings, "SHORTENERS", DEFAULT_CONFIG.SHORTENERS))
    cfg.SUSPICIOUS_BRAND_WORDS = set(getattr(settings, "SUSPICIOUS_BRAND_WORDS", DEFAULT_CONFIG.SUSPICIOUS_BRAND_WORDS))
    cfg.URGENCY_PATTERNS = list(getattr(settings, "URGENCY_PATTERNS", DEFAULT_CONFIG.URGENCY_PATTERNS))
    cfg.CONTEXT_WORDS = list(getattr(settings, "CONTEXT_WORDS", DEFAULT_CONFIG.CONTEXT_WORDS))
    cfg.DEFAULT_THRESHOLDS = getattr(settings, "DEFAULT_THRESHOLDS", DEFAULT_CONFIG.DEFAULT_THRESHOLDS)
    return cfg


# Utilities
_url_extractor = URLExtract()

def _normalize_text(text: str) -> str:
    return (text or "").strip()

def _find_urls(text: str):
    """Extrai URLs de forma robusta, incluindo patterns sem protocolo."""
    urls = []
    try:
        urls = _url_extractor.find_urls(text)
    except Exception as e:
        logger.debug("urlextract failed: %s", e)
        urls = []

    # Regex complementar (lowercase recomendado)
    extra = re.findall(r"(?:https?://)?(?:www\.)?[a-z0-9\-]+(?:\.[a-z]{2,})+(?:/[^\s<>\"']*)?", text.lower())
    for u in extra:
        if u and u not in urls:
            urls.append(u)
    return urls

def _extract_path_after_domain(raw_url: str):
    """Retorna o path do URL, adicionando esquema se necessário."""
    tmp = raw_url
    if not re.match(r"^[a-z]+://", raw_url):
        tmp = "http://" + raw_url
    try:
        p = urlparse(tmp)
        return p.path or ""
    except Exception:
        return ""

# Heurística
def check_phishing_heuristics(subject: str, body: str, config: SimpleNamespace = None):
    """
    Retorna: score:int, reasons:list[str], features:dict
    """
    if config is None:
        config = _get_config()

    score = 0
    reasons_set = set()  # evita duplicação de reasons
    features = {
        "has_link": 0,
        "num_links": 0,
        "has_ip_link": 0,
        "has_shortener": 0,
        "has_suspicious_domain": 0,
        "has_suspicious_tld": 0,
        "has_urgency": 0,
        "has_sensitive_request": 0,
        "path_brand_mismatch": 0,
        "num_exclamations": 0,
        "caps_ratio": 0.0,
        "num_words": 0,
    }

    text = _normalize_text((subject or "") + "\n" + (body or ""))
    text_lower = text.lower()

    # textual features
    features["num_exclamations"] = text.count("!")
    words = re.findall(r"\w+", text_lower)
    features["num_words"] = len(words)
    features["caps_ratio"] = sum(1 for c in text if c.isupper()) / max(1, len(text))

    # URLs
    urls = _find_urls(text_lower)
    features["num_links"] = len(urls)
    features["has_link"] = 1 if urls else 0

    logger.debug("Detected URLs: %s", urls)

    # análise de URLs
    for u in urls:
        u_raw = u.strip().strip(".,;:()[]<>\"'")
        u_for_parse = u_raw
        if not re.match(r"^[a-z]+://", u_for_parse):
            u_for_parse = "http://" + u_for_parse

        # detecta IP-style link
        if re.match(r"https?://\d{1,3}(?:\.\d{1,3}){3}", u_for_parse) or re.match(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/|$)", u_raw):
            score += 5
            reasons_set.add(f"URL com IP: {u_raw}")
            features["has_ip_link"] = 1

        # tldextract e components
        try:
            ext = tldextract.extract(u_for_parse)
            domain = (ext.domain or "").lower()
            suffix = (ext.suffix or "").lower()
            subdomain = (ext.subdomain or "").lower()
            root = f"{domain}.{suffix}" if domain and suffix else domain
        except Exception:
            domain = ""
            suffix = ""
            subdomain = ""
            root = u_raw.lower()

        # heurísticas de domínio/TLD
        if root and root in {d.lower() for d in config.SUSPICIOUS_DOMAINS}:
            score += 5
            reasons_set.add(f"Domínio suspeito: {root}")
            features["has_suspicious_domain"] = 1
        if suffix and suffix in {t.lower() for t in config.SUSPICIOUS_TLDS}:
            score += 2
            reasons_set.add(f"TLD suspeito: .{suffix}")
            features["has_suspicious_tld"] = 1
        if root and root in {s.lower() for s in config.SHORTENERS}:
            score += 3
            reasons_set.add(f"Encurtador detectado: {root}")
            features["has_shortener"] = 1
        if domain and any(b in domain for b in {b_.lower() for b_ in config.SUSPICIOUS_BRAND_WORDS}):
            score += 2
            reasons_set.add(f"Domínio genérico suspeito: {domain}")
            features["has_suspicious_domain"] = 1

        # path-based tricks
        path = _extract_path_after_domain(u_for_parse).lower()
        for brand in {b.lower() for b in config.SUSPICIOUS_BRAND_WORDS}:
            if brand in path and brand not in (root or ""):
                score += 5
                reasons_set.add(f"Brand/palavra suspeita '{brand}' encontrada no path de {root or u_raw}")
                features["path_brand_mismatch"] = 1
                break
        if re.search(r"/[a-z0-9\-]+\.[a-z]{2,4}($|/)", path):
            score += 3
            reasons_set.add(f"Path contendo padrão de domínio: {u_raw}")
        if re.search(r"[^\x00-\x7F]", u_raw):
            score += 1
            reasons_set.add(f"Caracteres não-ASCII na URL: {u_raw}")

    # textual heuristics (fora das URLs)
    if any(pat in text_lower for pat in {p.lower() for p in config.URGENCY_PATTERNS}):
        score += 4
        reasons_set.add("Mensagem com tom de urgência ou bloqueio")
        features["has_urgency"] = 1

    sensitive_detected = any(s in text_lower for s in {s_.lower() for s_ in config.SENSITIVE_KEYWORDS})
    context_detected = any(cw in text_lower for cw in {c.lower() for c in config.CONTEXT_WORDS})

    if sensitive_detected and context_detected:
        score += 4
        reasons_set.add("Solicita dados sensíveis em contexto de ação")
        features["has_sensitive_request"] = 1

    # NOVO: reforço CNH/Detran
    critical_keywords = ["cnh", "detran", "registro de veículo", "habilitação", "registro de habilitação"]
    if any(k in text_lower for k in critical_keywords) and features["has_link"]:
        score += 3
        reasons_set.add("Conteúdo crítico CNH/Detran detectado com link")

    # outros sinais
    if features["num_links"] >= 2:
        score += 1
        reasons_set.add(f"{features['num_links']} links detectados")
    if features["num_exclamations"] >= 3 or features["caps_ratio"] > 0.45:
        score += 1
        reasons_set.add("Uso excessivo de EXCLAMAÇÕES/MAIÚSCULAS")

    reasons = sorted(reasons_set)
    logger.debug("Heuristic score: %s, reasons: %s, features: %s", score, reasons, features)

    return score, reasons, features


# Integração heurística + ML
def classify_email(subject: str, body: str, ml_result: dict = None, config: SimpleNamespace = None):
    if config is None:
        config = _get_config()

    score, reasons, features = check_phishing_heuristics(subject, body, config=config)
    details = {"heur_score": int(score), "reasons": reasons, "features": features, "ml_result": ml_result}

    # cutoff heurística forte
    if score >= config.DEFAULT_THRESHOLDS.QUARANTINE_SCORE:
        return "PHISHING", details

    # integração ML
    if ml_result is not None:
        ml_label = str(ml_result.get("resultado") or "").upper()
        try:
            conf = float(ml_result.get("confiança") or ml_result.get("confidence") or 0.0)
        except Exception:
            conf = 0.0
        details["ml_confidence"] = conf

        if ml_label in ("SUSPEITO", "PHISHING") and conf >= 85.0:
            return "PHISHING", details
        elif ml_label in ("SUSPEITO", "PHISHING") and conf >= 70.0:
            return "SUSPEITO", details

    # cutoff heurística moderada
    if score >= config.DEFAULT_THRESHOLDS.SUSPECT_SCORE:
        return "SUSPEITO", details

    return "OK", details

