import os
import glob
import joblib
import re
import pandas as pd
from scipy.sparse import hstack, csr_matrix
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from core.preprocess import extract_features, preprocess_text
from config.settings import MODEL_PATH, VECTORIZER_PATH, THRESHOLD
from config.settings import MODEL_PATH, VECTORIZER_PATH, THRESHOLD

def train_model(folder_path: str):
    all_files = glob.glob(os.path.join(folder_path, "*.csv"))
    if not all_files:
        print("Nenhum CSV encontrado no diretório:", folder_path)
        return

    df_list = [pd.read_csv(file) for file in all_files]
    df = pd.concat(df_list, ignore_index=True)
    if 'text_combined' not in df.columns or 'label' not in df.columns:
        raise ValueError("Os CSVs devem conter as colunas 'text_combined' e 'label'.")

    df = df[['text_combined', 'label']].dropna()
    df = extract_features(df)

    X_text = df['text_clean']
    y = df['label']
    X_extra = df[['has_link','has_suspicious_words','num_exclamations','num_words']]

    X_train_text, X_test_text, y_train, y_test, X_train_extra, X_test_extra = train_test_split(
    X_text, y, X_extra, test_size=0.2, random_state=42
    )

    vectorizer = TfidfVectorizer(max_features=5000)
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
    if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
        raise FileNotFoundError("Modelo ou vetorizador não encontrado. Rode train_model() primeiro.")
    clf = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)
    return clf, vectorizer

def predict_email_model(text: str, clf, vectorizer, threshold: float = THRESHOLD):
    text_clean = preprocess_text(text)
    has_link = int(bool(re.search(r'http[s]?://', text)))
    has_suspicious_words = int(any(word in text_clean for word in ['prêmio','clique','ganhou','senha','conta','atualize','urgente','gratuito']))
    num_exclamations = text.count('!')
    num_words = len(text_clean.split())

    vec = vectorizer.transform([text_clean])
    extra_features = csr_matrix([[has_link, has_suspicious_words, num_exclamations, num_words]])
    X_final = hstack([vec, extra_features])

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