
import logging
from pathlib import Path

LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    # evita múltiplos handlers duplicados
    if logger.hasHandlers():
        return logger

    # Formato com horário e origem
    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console handler com suporte a UTF-8
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(fmt)
    # força UTF-8 no Windows
    try:
        console_handler.stream.reconfigure(encoding='utf-8')
    except Exception:
        pass

    # Arquivo de log (também UTF-8)
    file_handler = logging.FileHandler(LOG_DIR / "phishingbot.log", encoding='utf-8')
    file_handler.setFormatter(fmt)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    return logger