import logging

logging.basicConfig(
    filename="soar.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger("SOAR")