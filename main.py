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

MAX_SNIPPET_LEN = 120  # comprimento máximo do snippet para log
MAX_REASON_LEN = 150   # comprimento máximo de cada reason

def truncate_text(text, length):
    """Trunca texto com reticências se exceder o tamanho."""
    return text if len(text) <= length else text[:length] + "..."

def main():
    logger = get_logger("main")

    folder_path = os.path.join("datasets", "phishing_dataset")

    # Treina modelo se necessário
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

        # -----------------------
        # Heurística
        # -----------------------
        score, reasons, features = check_phishing_heuristics(subject, body)

        # -----------------------
        # ML
        # -----------------------
        ml_reason = ""
        try:
            model_result = predict_email_model(text_full, clf, vectorizer)
            if model_result["resultado"] == "SUSPEITO" and (
                model_result["features"].get("has_link") or model_result["features"].get("has_suspicious_words")
            ):
                score += 5
            ml_reason = f"ML: {truncate_text(str(model_result), MAX_REASON_LEN)}"
            reasons.append(ml_reason)
        except Exception as e:
            ml_reason = f"ML erro: {e}"
            reasons.append(ml_reason)

        # -----------------------
        # Vertex AI
        # -----------------------
        vertex_reason = ""
        if score < 5:
            try:
                vertex_result = vertex_moderator(subject, body)
                if "suspeito" in vertex_result.lower():
                    score += 5
                vertex_reason = f"Vertex AI: {truncate_text(vertex_result, MAX_REASON_LEN)}"
                reasons.append(vertex_reason)
            except Exception as e:
                vertex_reason = f"Vertex AI falhou: {e}"
                reasons.append(vertex_reason)

        # -----------------------
        # Log final
        # -----------------------
        snippet = truncate_text(msg.get("snippet", "").replace("\n", " "), MAX_SNIPPET_LEN)
        reasons_str = "; ".join([truncate_text(r, MAX_REASON_LEN) for r in reasons])

        if score >= 5:
            if settings.DRY_RUN:
                logger.info(f"[SUSPEITO] {mid} | {reasons_str} | {snippet}")
            else:
                apply_label_and_archive(service, mid, label_id)
                logger.warning(f"[QUARENTENA] {mid} | {reasons_str} | {snippet}")
        else:
            logger.info(f"[OK] {mid} | {snippet}")


if __name__ == "__main__":
    main()