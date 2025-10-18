import re
import pandas as pd
from unidecode import unidecode
from config.settings import SUSPICIOUS_WORDS

def preprocess_text(text: str) -> str:
    text = str(text or "").lower()
    text = unidecode(text)
    text = re.sub(r'[^a-zA-Z\s]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df['text_clean'] = df['text_combined'].apply(preprocess_text)
    df['has_link'] = df['text_combined'].str.contains(r'http[s]?://', na=False).astype(int)
    df['has_suspicious_words'] = df['text_clean'].apply(
lambda x: int(any(word in x for word in SUSPICIOUS_WORDS))
)
    df['num_exclamations'] = df['text_combined'].str.count('!', na=False)
    df['num_words'] = df['text_clean'].str.split().apply(lambda x: len(x) if isinstance(x, list) else 0)
    return df