import os
from utils.logger import get_logger
from core.model import train_model, load_model, predict_email_model
from core.heuristics import check_phishing_heuristics
from core.vertex_ai import vertex_moderator
from core.gmail_service import (
    get_service, ensure_label, list_candidate_ids,
    get_message, decode_body, apply_label_and_archive
)
from config import settings


def main():
    logger = get_logger("main")

    folder_path = os.path.join("datasets", "phishing_dataset")

    if not os.path.exists(settings.MODEL_PATH) or not os.path.exists(settings.VECTORIZER_PATH):
        logger.info("Treinando modelo com 4 features extras...")
        train_model(folder_path)

    clf, vectorizer = load_model()
    service = get_service()
    label_id = ensure_label(service)
    ids = list_candidate_ids(service, max_results=50)

    if not ids:
        logger.warning("Nenhuma mensagem encontrada.")
        return

    logger.info(f"Analisando {len(ids)} mensagens... (DRY_RUN={settings.DRY_RUN})")

    for mid in ids:
        msg = get_message(service, mid)
        headers = msg["payload"].get("headers", [])
        subject = next((h["value"] for h in headers if h["name"].lower() == "subject"), "")
        body = decode_body(msg["payload"])
        text_full = subject + "\n" + body

        score, reasons = check_phishing_heuristics(subject, body)

        try:
            model_result = predict_email_model(text_full, clf, vectorizer)
            if model_result["resultado"] == "SUSPEITO" and (
                model_result["features"]["has_link"] or model_result["features"]["has_suspicious_words"]
            ):
                score += 5
            reasons.append(f"Modelo ML: {model_result}")
        except Exception as e:
            reasons.append(f"Erro modelo ML: {e}")

        if score < 5:
            try:
                vertex_result = vertex_moderator(subject, body)
                if "suspeito" in vertex_result.lower():
                    score += 5
                reasons.append(f"Vertex AI: {vertex_result}")
            except Exception as e:
                reasons.append(f"Vertex AI falhou: {e}")

        snippet = msg.get("snippet", "").replace("\n", " ")[:120]

        if score >= 5:
            if settings.DRY_RUN:
                logger.info(f"[SUSPEITO] {mid} | {', '.join(reasons)} | {snippet}")
            else:
                apply_label_and_archive(service, mid, label_id)
                logger.warning(f"[QUARENTENA] {mid} | {', '.join(reasons)} | {snippet}")
        else:
            logger.info(f"[OK] {mid} | {snippet}")


if __name__ == "__main__":
    main()
