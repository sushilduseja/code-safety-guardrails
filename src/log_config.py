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


class StructuredFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(
            {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "level": record.levelname,
                "logger": record.name,
                "request_id": get_request_id(),
                "message": record.getMessage(),
            },
            default=str,
        )


def setup_logging() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(StructuredFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.INFO)
