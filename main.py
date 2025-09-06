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

from google.oauth2 import service_account
from google.cloud import aiplatform

# ---------------------- Configurações ----------------------
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
TOKEN_PATH = "token.json"
CREDS_PATH = "credentials.json"
VERTEX_CREDS = "vertex-ia-sa.json"
DRY_RUN = True  # Não move emails

PROJECT_ID = "gmail-anti-phishing-bot"
REGION = "us-central1"
VERTEX_MODEL_NAME = "text-bison@001"

# ---------------------- Vertex AI ----------------------
vertex_credentials = service_account.Credentials.from_service_account_file(VERTEX_CREDS)
aiplatform.init(project=PROJECT_ID, location=REGION, credentials=vertex_credentials)

# Cria instância do modelo
vertex_model = aiplatform.TextGenerationModel.from_pretrained(VERTEX_MODEL_NAME)

def vertex_moderator(subject: str, body: str) -> str:
    """
    Vertex decide sozinho se o email é phishing.
    Retorna 'SUSPEITO' ou 'OK' com explicação curta.
    """
    prompt = f"""
Você é um moderador de emails especialista em phishing.
Classifique o email como 'SUSPEITO' ou 'OK'.
Explique em 1-2 frases rapidamente.

Assunto: {subject}
Corpo: {body}
"""
    response = vertex_model.predict(prompt, max_output_tokens=150)
    return response.text.strip()

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

def list_candidate_ids(service, max_results=30):
    q = 'in:inbox newer_than:7d'
    resp = service.users().messages().list(userId="me", q=q, maxResults=max_results).execute()
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
        body={"name": name, "labelListVisibility":"labelShow","messageListVisibility":"show"}
    ).execute()
    return lbl["id"]

def apply_label_and_archive(service, msg_id, label_id):
    service.users().messages().modify(
        userId="me", id=msg_id,
        body={"addLabelIds":[label_id], "removeLabelIds":["INBOX"]}
    ).execute()

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
        subject = next((h["value"] for h in headers if h["name"].lower() == "subject"), "")
        body = decode_body(msg["payload"])

        try:
            vertex_result = vertex_moderator(subject, body)
            score = 5 if "suspeito" in vertex_result.lower() else 0
        except Exception as e:
            vertex_result = f"Vertex falhou: {e}"
            score = 0

        snippet = msg.get("snippet","").replace("\n"," ")[:120]

        if score >= 3:
            if DRY_RUN:
                print(f"[SUSPEITO] id={mid} | {vertex_result} | snippet: {snippet}")
            else:
                apply_label_and_archive(service, mid, label_id)
                print(f"[QUARENTENA] id={mid} | {vertex_result} | snippet: {snippet}")
        else:
            print(f"[OK] id={mid} | snippet: {snippet}")

if __name__ == "__main__":
    main()
