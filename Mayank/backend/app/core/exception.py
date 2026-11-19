from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from app.core.logger import logger


async def validation_exception_handler(request: Request, exc: Exception):
    try:
        raw_errors = getattr(exc, "errors", lambda: str(exc))()
        safe_errors = jsonable_encoder(raw_errors)
    except Exception:
        safe_errors = str(exc)

    logger.warning(f"Validation error on {request.method} {request.url.path}: {safe_errors}")
    return JSONResponse(
        status_code=422,
        content={
            "status": "error",
            "message": "Input validation failed. Please check field formats and required parameters.",
            "details": safe_errors
        }
    )


async def generic_exception_handler(request: Request, exc: Exception):
    if isinstance(exc, (RequestValidationError, ValidationError)):
        return await validation_exception_handler(request, exc)

    # Log internal error and trace safely on the server side
    logger.error(f"Unhandled exception processing {request.method} {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "message": "An internal server error occurred while processing the security request. Detailed log recorded for SOC administrator."
        }
    )