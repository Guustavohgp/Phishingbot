import os
import base64
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from config.settings import SCOPES, TOKEN_PATH, CREDS_PATH

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
        except Exception:
            return ""
    parts = payload.get("parts", []) or []
    text = []
    for p in parts:
        text.append(decode_body(p))
    return "\n".join([t for t in text if t])


def list_candidate_ids(service, max_results=30, q='in:inbox newer_than:7d'):
    resp = service.users().messages().list(userId="me", q=q, maxResults=max_results).execute()
    return [m["id"] for m in resp.get("messages", [])]

def get_message(service, msg_id):
    return service.users().messages().get(userId="me", id=msg_id, format="full").execute()

def ensure_label(service, name="Quarentena-Phishing"):
    labels = service.users().labels().list(userId="me").execute().get("labels", [])
    for l in labels:
        if l["name"] == name:
            return l["id"]
    lbl = service.users().labels().create(
        userId="me",
        body={"name": name, "labelListVisibility": "labelShow", "messageListVisibility": "show"}
    ).execute()
    return lbl["id"]

def apply_label_and_archive(service, msg_id, label_id):
    service.users().messages().modify(
        userId="me",
        id=msg_id,
        body={
            "addLabelIds": [label_id],
            "removeLabelIds": ["INBOX"]
        }
    ).execute()


if __name__ == "__main__":
    service = get_service()
    label_id = ensure_label(service)

    for msg_id in list_candidate_ids(service):
        message = get_message(service, msg_id)
        body = decode_body(message["payload"])
        # Aqui você pode adicionar lógica para detectar phishing
        if "suspeito" in body.lower():
            apply_label_and_archive(service, msg_id, label_id)
            print(f"Mensagem {msg_id} movida para Quarentena-Phishing.")