from __future__ import annotations
import os, base64
from email.utils import parseaddr
from urllib.parse import urlparse

import tldextract
from urlextract import URLExtract

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

# ===== Configurações =====
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
TOKEN_PATH = "token.json"
CREDS_PATH = "credentials.json"

# Modo simulação: True = NÃO move/arquiva, só loga. Quando calibrar, mude para False.
DRY_RUN = False

# Heurísticas simples
SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "gq", "tk"}
BRAND_DOMAINS = {"google.com","gmail.com","paypal.com","microsoft.com","apple.com","facebook.com","meta.com","nubank.com.br","itau.com.br",}

def get_service():
    creds = None
    if os.path.exists(TOKEN_PATH):
        creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not os.path.exists(CREDS_PATH):
                raise FileNotFoundError("credentials.json não encontrado na pasta do projeto.")
            flow = InstalledAppFlow.from_client_secrets_file(CREDS_PATH, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(TOKEN_PATH, "w") as f:
            f.write(creds.to_json())
    return build("gmail", "v1", credentials=creds)

def get_header(headers, name):
    for h in headers:
        if h.get("name","").lower() == name.lower():
            return h.get("value","")
    return ""

def decode_body(payload) -> str:
    """Extrai texto de partes text/plain e text/html (sem transformar HTML)."""
    if "data" in payload.get("body", {}):
        try:
            data = payload["body"]["data"]
            return base64.urlsafe_b64decode(data.encode("UTF-8")).decode("UTF-8", errors="ignore")
        except Exception:
            return ""
    text = []
    for p in payload.get("parts", []) or []:
        text.append(decode_body(p))
    return "\n".join([t for t in text if t])

def extract_urls(text: str):
    extractor = URLExtract()
    urls = extractor.find_urls(text or "")
    # Remove duplicatas simples
    return list(dict.fromkeys(urls))

def domain_info(url: str):
    try:
        p = urlparse(url)
        ext = tldextract.extract(p.netloc)
        root = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        return root.lower(), ext.suffix.lower()
    except Exception:
        return "", ""

def looks_like_brand_impersonation(display_name: str, from_addr: str) -> bool:
    # Ex: “Suporte Google <conta@nao-google.com>”
    name, email = parseaddr(f"{display_name} <{from_addr}>")
    ext = tldextract.extract(email.split("@")[-1]) if "@" in email else tldextract.extract("")
    root = f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ext.domain.lower()
    suspicious_name = any(b in (name or "").lower() for b in ["google","microsoft","paypal","itau","nubank","meta","facebook","apple"])
    return bool(suspicious_name and root not in BRAND_DOMAINS)

def phishing_score(msg):
    headers = msg["payload"].get("headers", [])
    from_h = get_header(headers, "From")
    subject = get_header(headers, "Subject")
    authres = get_header(headers, "Authentication-Results")
    received_spf = get_header(headers, "Received-SPF")
    body = decode_body(msg["payload"])

    urls = extract_urls((subject or "") + "\n" + (body or ""))

    score = 0
    reasons = []

    # Display name spoof
    if looks_like_brand_impersonation(from_h, from_h):
        score += 2; reasons.append("Remetente parece se passar por marca conhecida.")

    # SPF/DKIM/DMARC (indícios)
    if "spf=fail" in (authres or "").lower() or "fail" in (received_spf or "").lower():
        score += 2; reasons.append("SPF falhou.")
    if "dkim=fail" in (authres or "").lower():
        score += 2; reasons.append("DKIM falhou.")
    if "dmarc=fail" in (authres or "").lower() or "dmarc=reject" in (authres or "").lower():
        score += 3; reasons.append("DMARC falhou.")

    # Links suspeitos
    for u in urls:
        root, tld = domain_info(u)
        if tld in SUSPICIOUS_TLDS:
            score += 1; reasons.append(f"TLD suspeito: .{tld}")
        if "xn--" in u:
            score += 1; reasons.append("Domínio punycode (possível homógrafo).")
        # URL que imita marca (exemplos)
        if any(fake in u.lower() for fake in ["secure-google.com","google.verify","account-google.","paypal-secure.","microsoft-support.","itau-verificacao.","nubank-seguro."]):
            score += 2; reasons.append("URL imita domínio de marca.")

    # Palavras-chave comuns
    bait = ["verifique sua conta","sua senha expira","clique para atualizar","pagamento pendente","confirme seus dados","atualize suas informações","bloqueio da conta"]
    blob = f"{subject or ''} {body or ''}".lower()
    if any(k in blob for k in bait):
        score += 1; reasons.append("Conteúdo com isca típica.")

    return score, reasons

def ensure_label(service, name="Quarentena-Phishing"):
    labels = service.users().labels().list(userId="me").execute().get("labels",[])
    for l in labels:
        if l["name"] == name:
            return l["id"]
    lbl = service.users().labels().create(
        userId="me",
        body={"name": name, "labelListVisibility":"labelShow","messageListVisibility":"show"}
    ).execute()
    return lbl["id"]

def apply_label_and_archive(service, msg_id, label_id):
    service.users().messages().modify(
        userId="me", id=msg_id,
        body={"addLabelIds":[label_id], "removeLabelIds":["INBOX"]}
    ).execute()

def list_candidate_ids(service, max_results=30):
    # Filtra a caixa de entrada recente (ajuste como preferir)
    q = 'in:inbox newer_than:7d'
    resp = service.users().messages().list(userId="me", q=q, maxResults=max_results).execute()
    return [m["id"] for m in resp.get("messages", [])]

def get_message(service, msg_id):
    return service.users().messages().get(userId="me", id=msg_id, format="full").execute()

def main():
    service = get_service()
    label_id = ensure_label(service)

    ids = list_candidate_ids(service, max_results=50)
    if not ids:
        print("Nenhuma mensagem encontrada no período filtrado.")
        return

    THRESHOLD = 3  # sensibilidade do detector
    print(f"Analisando {len(ids)} mensagens... (DRY_RUN={DRY_RUN})")

    for mid in ids:
        msg = get_message(service, mid)
        score, reasons = phishing_score(msg)
        snippet = msg.get("snippet","").replace("\n"," ")[:120]
        if score >= THRESHOLD:
            if DRY_RUN:
                print(f"[SUSPEITO] id={mid} score={score} | {', '.join(reasons)} | snippet: {snippet}")
            else:
                apply_label_and_archive(service, mid, label_id)
                print(f"[QUARENTENA] id={mid} score={score} | {', '.join(reasons)} | snippet: {snippet}")
        else:
            print(f"[OK] id={mid} score={score} | snippet: {snippet}")

if __name__ == "__main__":
    main()
