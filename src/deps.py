from fastapi import Request

from src.generator import CodeGenerator
from src.telemetry import Telemetry


def get_code_generator(request: Request) -> CodeGenerator:
    return request.app.state.code_generator


def get_telemetry(request: Request) -> Telemetry:
    return request.app.state.telemetry
