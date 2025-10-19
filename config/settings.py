import os
from google.generativeai import configure

# ---------------------- Configurações Gerais ----------------------
BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, '..'))

SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

# Paths (assumindo que credentials/token estão na raiz do projeto)
TOKEN_PATH = os.path.join(PROJECT_ROOT, "token.json")
CREDS_PATH = os.path.join(BASE_DIR, "credentials.json")
VERTEX_CREDS = os.path.join(PROJECT_ROOT, "vertex-ia-sa.json")

# Model paths
MODEL_PATH = os.path.join(PROJECT_ROOT, "phishing_model.pkl")
VECTORIZER_PATH = os.path.join(PROJECT_ROOT, "tfidf_vectorizer.pkl")

# Dados
DATASETS_FOLDER = os.path.join(PROJECT_ROOT, "datasets", "phishing_dataset")

# Comportamento
THRESHOLD = 0.7
DRY_RUN = True # padrão seguro: True -> não move e-mails

SUSPICIOUS_TLDS = {"zip","mov","xyz","top","gq","tk"}
SUSPICIOUS_DOMAINS = {"itau-fatura.com", "google-conta.com"}
SENSITIVE_KEYWORDS = [
"cpf","cartão","senha","rg","confirme suas credenciais",
"pague agora","bloqueio da conta","verifique sua conta",
"senha expirada","prêmio","ganhou","resgatar"
]
SUSPICIOUS_WORDS = ["prêmio", "clique", "ganhou", "senha", "conta", "atualize", "urgente", "gratuito"]

# Configurar Vertex AI (usar variável de ambiente ou service account key)
os.environ.setdefault("GOOGLE_APPLICATION_CREDENTIALS", VERTEX_CREDS)
configure(api_key=None)