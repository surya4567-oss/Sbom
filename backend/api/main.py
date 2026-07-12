"""FastAPI application entry point."""

from __future__ import annotations

import os
import sys

# Ensure project root is on sys.path for legacy module imports
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.api.routes import router
from backend.services.analysis_state import get_state


@asynccontextmanager
async def lifespan(_app: FastAPI):
    get_state()
    yield


app = FastAPI(
    title="SBOM Risk Analyzer API",
    description="Software Supply Chain Risk Analyzer — REST API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")


@app.exception_handler(ValueError)
async def value_error_handler(_request: Request, exc: ValueError):
    return JSONResponse(status_code=422, content={"detail": str(exc), "code": "VALIDATION_ERROR"})


@app.get("/health")
def health():
    return {"status": "ok"}


def run():
    import uvicorn

    uvicorn.run("backend.api.main:app", host="0.0.0.0", port=8000, reload=True)
