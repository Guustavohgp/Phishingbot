from __future__ import annotations
import os
import base64
from email.utils import parseaddr
from urllib.parse import urlparse
from datetime import datetime

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

import tldextract
from urlextract import URLExtract
import google.generativeai as genai

# ---------------------- Configurações ----------------------
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
TOKEN_PATH = "token.json"
CREDS_PATH = "credentials.json"
VERTEX_CREDS = "vertex-ia-sa.json"
DRY_RUN = True # Modo Simulação 

# Domínios e TLDs suspeitos
SUSPICIOUS_TLDS = {"zip","mov","xyz","top","gq","tk"}
SUSPICIOUS_DOMAINS = {"itau-fatura.com", "google-conta.com"}

# Palavras-chave sensíveis
SENSITIVE_KEYWORDS = [
    "nome", "cpf", "rg", "senha", "login", "cartão", "dados bancários",
    "informações pessoais", "prêmio", "resgatar", "pague agora", "bloqueio da conta",
    "verifique sua conta", "confirme suas credenciais"
]

# Histórico de análises (para aprendizado contínuo)
HISTORIC_LOG = "phishing_history.log"

os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = VERTEX_CREDS
genai.configure(api_key=None)

# ---------------------- Vertex AI ----------------------
def vertex_moderator(subject: str, body: str) -> str:
    prompt = f"""
Você é um moderador de emails especialista em phishing.
Classifique o email como 'SUSPEITO' ou 'OK'.
Explique em 1-2 frases rapidamente.
Sempre considere phishing qualquer tentativa de:
- Solicitar dados pessoais
- Pressionar para pagamento ou urgência
- Usar domínios suspeitos ou TLDs estranhos
Assunto: {subject}
Corpo: {body}
"""
    response = genai.generate_text(
        model="gemini-1.0-pro",
        prompt=prompt,
        max_output_tokens=200
    )
    return response.result.strip()

# ---------------------- Heurísticas ----------------------
def check_phishing_heuristics(subject: str, body: str) -> (int, list[str]):
    score = 0
    reasons = []

    text = (subject or "") + "\n" + (body or "")
    text_lower = text.lower()
    extractor = URLExtract()
    urls = extractor.find_urls(text)

    # URLs suspeitas
    for u in urls:
        ext = tldextract.extract(u)
        root = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        tld = ext.suffix
        if u in SUSPICIOUS_DOMAINS or root in SUSPICIOUS_DOMAINS:
            score += 5
            reasons.append(f"Domínio suspeito: {u}")
        if tld in SUSPICIOUS_TLDS:
            score += 1
            reasons.append(f"TLD suspeito: .{tld}")

    # Solicitação de dados pessoais ou urgência
    for word in SENSITIVE_KEYWORDS:
        if word in text_lower:
            score += 5
            reasons.append(f"Contém palavra sensível: '{word}'")
            break  # Só precisa marcar uma vez

    return score, reasons

# ---------------------- Gmail API ----------------------
def get_service():
    creds = None
    if os.path.exists(TOKEN_PATH):
        creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CREDS_PATH, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(TOKEN_PATH, "w") as f:
            f.write(creds.to_json())
    return build("gmail", "v1", credentials=creds)

def decode_body(payload) -> str:
    if "data" in payload.get("body", {}):
        try:
            return base64.urlsafe_b64decode(payload["body"]["data"].encode("UTF-8")).decode("UTF-8", errors="ignore")
        except:
            return ""
    text = []
    for p in payload.get("parts", []) or []:
        text.append(decode_body(p))
    return "\n".join([t for t in text if t])

def list_candidate_ids(service, max_results=30):
    resp = service.users().messages().list(userId="me", q='in:inbox newer_than:7d', maxResults=max_results).execute()
    return [m["id"] for m in resp.get("messages", [])]

def get_message(service, msg_id):
    return service.users().messages().get(userId="me", id=msg_id, format="full").execute()

def ensure_label(service, name="Quarentena-Phishing"):
    labels = service.users().labels().list(userId="me").execute().get("labels",[])
    for l in labels:
        if l["name"] == name:
            return l["id"]
    lbl = service.users().labels().create(
        userId="me",
        body={"name": name,"labelListVisibility":"labelShow","messageListVisibility":"show"}
    ).execute()
    return lbl["id"]

def apply_label_and_archive(service, msg_id, label_id):
    service.users().messages().modify(
        userId="me", id=msg_id,
        body={"addLabelIds":[label_id],"removeLabelIds":["INBOX"]}
    ).execute()

# ---------------------- Logging ----------------------
def log_email(subject: str, snippet: str, score: int, reasons: list[str]):
    with open(HISTORIC_LOG, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now()} | Score={score} | Reasons={reasons} | Subject={subject[:50]} | Snippet={snippet}\n")

# ---------------------- Main ----------------------
def main():
    service = get_service()
    label_id = ensure_label(service)

    ids = list_candidate_ids(service, max_results=50)
    if not ids:
        print("Nenhuma mensagem encontrada.")
        return

    print(f"Analisando {len(ids)} mensagens... (DRY_RUN={DRY_RUN})")

    for mid in ids:
        msg = get_message(service, mid)
        headers = msg["payload"].get("headers", [])
        subject = next((h["value"] for h in headers if h["name"].lower()=="subject"), "")
        body = decode_body(msg["payload"])
        snippet = msg.get("snippet","").replace("\n"," ")[:120]

        # Heurísticas
        score, reasons = check_phishing_heuristics(subject, body)

        # Vertex AI se heurísticas não detectarem
        if score < 5:
            try:
                vertex_result = vertex_moderator(subject, body)
                if "suspeito" in vertex_result.lower():
                    score += 5
                reasons.append(f"Vertex AI: {vertex_result}")
            except Exception as e:
                reasons.append(f"Vertex AI falhou: {e}")

        # Log histórico
        log_email(subject, snippet, score, reasons)

        # Decisão final
        if score >= 5:
            if DRY_RUN:
                print(f"[SUSPEITO] id={mid} | {', '.join(reasons)} | snippet: {snippet}")
            else:
                apply_label_and_archive(service, mid, label_id)
                print(f"[QUARENTENA] id={mid} | {', '.join(reasons)} | snippet: {snippet}")
        else:
            print(f"[OK] id={mid} | snippet: {snippet}")

if __name__ == "__main__":
    main()
