from __future__ import annotations
import os
import base64
import re
from email.utils import parseaddr
from urllib.parse import urlparse
import glob
import pandas as pd
import joblib
from scipy.sparse import hstack, csr_matrix
from unidecode import unidecode
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

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
DRY_RUN = True

MODEL_PATH = "phishing_model.pkl"
VECTORIZER_PATH = "tfidf_vectorizer.pkl"
THRESHOLD = 0.7

SUSPICIOUS_TLDS = {"zip","mov","xyz","top","gq","tk"}
SUSPICIOUS_DOMAINS = {"itau-fatura.com", "google-conta.com"}
SENSITIVE_KEYWORDS = [
    "cpf","cartão","senha","rg","confirme suas credenciais",
    "pague agora","bloqueio da conta","verifique sua conta",
    "senha expirada","prêmio","ganhou","resgatar"
]
SUSPICIOUS_WORDS = ["prêmio", "clique", "ganhou", "senha", "conta", "atualize", "urgente", "gratuito"]

os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = VERTEX_CREDS
genai.configure(api_key=None)

# ---------------------- Funções ----------------------
def preprocess_text(text: str) -> str:
    text = str(text).lower()
    text = unidecode(text)
    text = re.sub(r'[^a-zA-Z\s]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df['text_clean'] = df['text_combined'].apply(preprocess_text)
    df['has_link'] = df['text_combined'].str.contains(r'http[s]?://').astype(int)
    df['has_suspicious_words'] = df['text_clean'].apply(
        lambda x: int(any(word in x for word in SUSPICIOUS_WORDS))
    )
    df['num_exclamations'] = df['text_combined'].str.count('!')
    df['num_words'] = df['text_clean'].str.split().apply(len)
    return df

def train_model(folder_path: str):
    all_files = glob.glob(os.path.join(folder_path, "*.csv"))
    if not all_files:
        print("Nenhum CSV encontrado no diretório:", folder_path)
        return

    df_list = [pd.read_csv(file) for file in all_files]
    df = pd.concat(df_list, ignore_index=True)
    df = df[['text_combined','label']].dropna()
    df = extract_features(df)

    X_text = df['text_clean']
    y = df['label']
    X_extra = df[['has_link','has_suspicious_words','num_exclamations','num_words']]

    X_train_text, X_test_text, y_train, y_test, X_train_extra, X_test_extra = train_test_split(
        X_text, y, X_extra, test_size=0.2, random_state=42
    )

    vectorizer = TfidfVectorizer(max_features=5000, stop_words=None)
    X_train_tfidf = vectorizer.fit_transform(X_train_text)
    X_test_tfidf = vectorizer.transform(X_test_text)

    X_train_final = hstack([X_train_tfidf, csr_matrix(X_train_extra.values)])
    X_test_final = hstack([X_test_tfidf, csr_matrix(X_test_extra.values)])

    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train_final, y_train)

    y_pred = clf.predict(X_test_final)
    print("\n--- Matriz de Confusão ---")
    print(confusion_matrix(y_test, y_pred))
    print("\n--- Relatório de Classificação ---")
    print(classification_report(y_test, y_pred))

    joblib.dump(clf, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    print("\nModelo e TF-IDF salvos com sucesso!")

def load_model():
    clf = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)
    return clf, vectorizer

def predict_email_model(text: str, clf, vectorizer, threshold=THRESHOLD):
    text_clean = preprocess_text(text)
    has_link = int(bool(re.search(r'http[s]?://', text)))
    has_suspicious_words = int(any(word in text_clean for word in SUSPICIOUS_WORDS))
    num_exclamations = text.count('!')
    num_words = len(text_clean.split())

    vec = vectorizer.transform([text_clean])
    extra_features = csr_matrix([[has_link, has_suspicious_words, num_exclamations, num_words]])
    X_final = hstack([vec, extra_features])

    print(f"Shape do vetor de entrada para predição: {X_final.shape}")

    probas = clf.predict_proba(X_final)[0]
    pred = 1 if probas[1] >= threshold else 0
    return {
        "resultado": "SUSPEITO" if pred==1 else "OK",
        "confiança": round(probas[1]*100,2),
        "features": {
            "has_link": has_link,
            "has_suspicious_words": has_suspicious_words,
            "num_exclamations": num_exclamations,
            "num_words": num_words
        }
    }

def check_phishing_heuristics(subject: str, body: str):
    """
    Avalia se um email é phishing baseado em palavras-chave, links suspeitos e contexto.
    Somente aumenta score se houver intenção de coletar dados pessoais ou urgência.
    """
    score = 0
    reasons = []

    text = (subject or "") + "\n" + (body or "")
    text_lower = text.lower()
    extractor = URLExtract()
    urls = extractor.find_urls(text)

    # 1️⃣ Verificar links suspeitos e TLDs
    for u in urls:
        root = tldextract.extract(u).domain + "." + tldextract.extract(u).suffix
        tld = tldextract.extract(u).suffix
        if u in SUSPICIOUS_DOMAINS or root in SUSPICIOUS_DOMAINS:
            score += 5
            reasons.append(f"Domínio suspeito: {u}")
        if tld in SUSPICIOUS_TLDS:
            score += 1
            reasons.append(f"TLD suspeito: .{tld}")

    # 2️⃣ Palavras sensíveis com contexto de coleta
    context_words = ["envie", "informe", "resgatar", "clique", "confirme", "forneça"]
    for word in SENSITIVE_KEYWORDS:
        if word.lower() in text_lower:
            # Verificar se aparece junto de palavra de ação/intenção
            if any(cw in text_lower for cw in context_words):
                score += 5
                reasons.append(f"Solicita dados pessoais: '{word}' com contexto de coleta")

    # 3️⃣ Mensagens com urgência
    urgency_words = ["pague agora","bloqueio da conta","verifique sua conta","senha expirada"]
    if any(word in text_lower for word in urgency_words):
        score += 3
        reasons.append("Mensagem com urgência ou pagamento imediato.")

    return score, reasons

def vertex_moderator(subject: str, body: str):
    prompt = f"""
Você é um moderador especialista em phishing.
Classifique o email como 'SUSPEITO' ou 'OK' com 1-2 frases de explicação.

Assunto: {subject}
Corpo: {body}
"""
    response = genai.generate_text(
        model="gemini-1.0-pro",
        prompt=prompt,
        max_output_tokens=150
    )
    return response.result.strip()

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
        with open(TOKEN_PATH,"w") as f:
            f.write(creds.to_json())
    return build("gmail","v1",credentials=creds)

def decode_body(payload) -> str:
    if "data" in payload.get("body",{}):
        try:
            return base64.urlsafe_b64decode(payload["body"]["data"].encode("UTF-8")).decode("UTF-8", errors="ignore")
        except:
            return ""
    text = []
    for p in payload.get("parts",[]) or []:
        text.append(decode_body(p))
    return "\n".join([t for t in text if t])

def list_candidate_ids(service, max_results=30):
    resp = service.users().messages().list(userId="me", q='in:inbox newer_than:7d', maxResults=max_results).execute()
    return [m["id"] for m in resp.get("messages",[])]

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

# ---------------------- Main ----------------------
def main():
    folder_path = os.path.join(os.path.dirname(__file__), "datasets", "phishing_dataset")
    if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
        print("Treinando modelo com 4 features extras...")
        train_model(folder_path)
    clf, vectorizer = load_model()

    service = get_service()
    label_id = ensure_label(service)
    ids = list_candidate_ids(service, max_results=50)
    if not ids:
        print("Nenhuma mensagem encontrada.")
        return

    print(f"Analisando {len(ids)} mensagens... (DRY_RUN={DRY_RUN})")

    for mid in ids:
        msg = get_message(service, mid)
        headers = msg["payload"].get("headers",[])
        subject = next((h["value"] for h in headers if h["name"].lower()=="subject"),"")
        body = decode_body(msg["payload"])
        text_full = subject + "\n" + body

        score, reasons = check_phishing_heuristics(subject, body)

        # Modelo ML
        try:
            model_result = predict_email_model(text_full, clf, vectorizer, THRESHOLD)
            if model_result["resultado"]=="SUSPEITO" and (
                model_result["features"]["has_link"] or
                model_result["features"]["has_suspicious_words"]
            ):
                score += 5
            reasons.append(f"Modelo ML: {model_result}")
        except Exception as e:
            reasons.append(f"Modelo ML falhou: {e}")

        # Vertex AI se heurística e ML não forem suficientes
        if score < 5:
            try:
                vertex_result = vertex_moderator(subject, body)
                if "suspeito" in vertex_result.lower():
                    score += 5
                reasons.append(f"Vertex AI: {vertex_result}")
            except Exception as e:
                reasons.append(f"Vertex AI falhou: {e}")

        snippet = msg.get("snippet","").replace("\n"," ")[:120]

        if score >=5:
            if DRY_RUN:
                print(f"[SUSPEITO] id={mid} | {', '.join(reasons)} | snippet: {snippet}")
            else:
                apply_label_and_archive(service, mid, label_id)
                print(f"[QUARENTENA] id={mid} | {', '.join(reasons)} | snippet: {snippet}")
        else:
            print(f"[OK] id={mid} | snippet: {snippet}")

if __name__=="__main__":
    main()
