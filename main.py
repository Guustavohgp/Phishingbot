from __future__ import annotations
import os
import base64
from email.utils import parseaddr
from urllib.parse import urlparse

import tldextract
from urlextract import URLExtract

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

# Biblioteca generativa do Vertex AI
import google.generativeai as genai

# ---------------------- Configurações ----------------------
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
TOKEN_PATH = "token.json"
CREDS_PATH = "credentials.json"
VERTEX_CREDS = "vertex-ia-sa.json"
DRY_RUN = True  # Teste seguro, não move emails

SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "gq", "tk"}
BRAND_DOMAINS = {
    "google.com","gmail.com","paypal.com","microsoft.com","apple.com",
    "facebook.com","meta.com","nubank.com.br","itau.com.br"
}

PROJECT_ID = "gmail-anti-phishing-bot"
REGION = "us-central1"

# ---------------------- Vertex AI ----------------------
os.environ["GOOGLE_API_KEY"] = VERTEX_CREDS
genai.configure(api_key=os.environ["GOOGLE_API_KEY"])

def vertex_moderator(subject: str, body: str) -> str:
    """
    Analisa email e retorna 'SUSPEITO' ou 'OK' com explicação breve.
    """
    prompt = f"""
Você é um moderador de emails especializado em identificar phishing. Analise o email e classifique como 'SUSPEITO' ou 'OK'.
Inclua uma breve explicação (1-2 frases).

Considere phishing qualquer tentativa de:
- Enganar o usuário para clicar em links maliciosos
- Solicitar dados pessoais, senhas ou informações financeiras
- Usar linguagem de urgência ou pressão
- Usar domínios suspeitos ou que imitam marcas

Email a ser analisado:
Assunto: {subject}
Corpo: {body}
"""
    response = genai.generate_text(
        model="gemini-1.0-pro",  # modelo atual de texto do Vertex
        prompt=prompt,
        max_output_tokens=150
    )
    return response.result.strip()

# ---------------------- Gmail API ----------------------
def get_service():
    creds = None
    if os.path.exists(TOKEN_PATH):
        creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not os.path.exists(CREDS_PATH):
                raise FileNotFoundError("credentials.json não encontrado.")
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
    name, email = parseaddr(f"{display_name} <{from_addr}>")
    ext = tldextract.extract(email.split("@")[-1]) if "@" in email else tldextract.extract("")
    root = f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ext.domain.lower()
    suspicious_name = any(b in (name or "").lower() for b in [
        "google","microsoft","paypal","itau","nubank","meta","facebook","apple"
    ])
    return bool(suspicious_name and root not in BRAND_DOMAINS)

# ---------------------- Phishing Score ----------------------
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

    # Heurísticas básicas
    if looks_like_brand_impersonation(from_h, from_h):
        score += 2
        reasons.append("Remetente parece se passar por marca conhecida.")
    if "spf=fail" in (authres or "").lower() or "fail" in (received_spf or "").lower():
        score += 2
        reasons.append("SPF falhou.")
    if "dkim=fail" in (authres or "").lower():
        score += 2
        reasons.append("DKIM falhou.")
    if "dmarc=fail" in (authres or "").lower() or "dmarc=reject" in (authres or "").lower():
        score += 3
        reasons.append("DMARC falhou.")
    for u in urls:
        root, tld = domain_info(u)
        if tld in SUSPICIOUS_TLDS:
            score += 1
            reasons.append(f"TLD suspeito: .{tld}")
        if "xn--" in u:
            score += 1
            reasons.append("Domínio punycode (possível homógrafo).")

    # Vertex AI
    try:
        vertex_result = vertex_moderator(subject, body)
        if "suspeito" in vertex_result.lower():
            score += 5
        reasons.append(f"Vertex AI: {vertex_result}")
    except Exception as e:
        reasons.append(f"Vertex AI falhou: {e}")

    return score, reasons

# ---------------------- Funções de label ----------------------
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
    q = 'in:inbox newer_than:7d'
    resp = service.users().messages().list(userId="me", q=q, maxResults=max_results).execute()
    return [m["id"] for m in resp.get("messages", [])]

def get_message(service, msg_id):
    return service.users().messages().get(userId="me", id=msg_id, format="full").execute()

# ---------------------- Main ----------------------
def main():
    service = get_service()
    label_id = ensure_label(service)

    ids = list_candidate_ids(service, max_results=50)
    if not ids:
        print("Nenhuma mensagem encontrada no período filtrado.")
        return

    THRESHOLD = 3
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
