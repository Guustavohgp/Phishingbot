from utils.logger import get_logger
from core.preprocess import preprocess_email
from core.model import train_model, load_model, predict_email
from core.heuristics import apply_heuristics
from core.vertex_ai import deploy_to_vertex_ai, predict_with_vertex
from config import settings
import os
import sys


def main():
    logger = get_logger("phishing_detector")

    logger.info("Iniciando o pipeline de detecção de phishing...")

    try:
        # 1️⃣ Carregar e preprocessar dataset
        dataset_path = os.path.join("datasets", "emails.csv")
        if not os.path.exists(dataset_path):
            logger.error(f"Dataset não encontrado: {dataset_path}")
            sys.exit(1)

        logger.info("Pré-processando dataset...")
        X_train, X_test, y_train, y_test = preprocess_email(dataset_path)

        # 2️⃣ Treinar ou carregar modelo existente
        model_path = "phishing_model.pkl"
        vectorizer_path = "tfidf_vectorizer.pkl"

        if os.path.exists(model_path):
            logger.info("Carregando modelo existente...")
            model, vectorizer = load_model(model_path, vectorizer_path)
        else:
            logger.info("Treinando novo modelo...")
            model, vectorizer = train_model(X_train, y_train, save=True)

        # 3️⃣ Avaliação local
        logger.info("Avaliando modelo localmente...")
        predictions = predict_email(model, vectorizer, X_test)
        heuristics_score = apply_heuristics(X_test)
        logger.info("Heurísticas aplicadas com sucesso.")

        # 4️⃣ Integração com Vertex AI (opcional)
        if settings.USE_VERTEX_AI:
            logger.info("Enviando modelo para o Vertex AI...")
            deploy_to_vertex_ai(model_path, vectorizer_path)
            vertex_result = predict_with_vertex("Exemplo de e-mail suspeito")
            logger.info(f"Predição Vertex AI: {vertex_result}")

        logger.info("Pipeline finalizado com sucesso ✅")

    except Exception as e:
        logger.exception(f"Erro durante a execução do pipeline: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()