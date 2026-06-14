import json
import logging
import contextvars
from datetime import datetime, timezone

_request_id: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="")


def set_request_id(rid: str) -> contextvars.Token[str]:
    return _request_id.set(rid)


def reset_request_id(token: contextvars.Token[str]) -> None:
    _request_id.reset(token)


def get_request_id() -> str:
    return _request_id.get()


class HumanReadableFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        rid = get_request_id()
        rid_str = f" [{rid}]" if rid else ""
        return f"{ts} [{record.levelname}] [{record.name}]{rid_str} {record.getMessage()}"


def setup_logging() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(HumanReadableFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.INFO)
