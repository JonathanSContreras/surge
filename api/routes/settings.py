import os
from typing import Literal, Optional

import httpx
from dotenv import load_dotenv
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

load_dotenv()

_OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")

_model_settings: dict = {
    "mode": "online",
    "online_model": "z-ai/glm-4.7",            # analysis tier
    "online_fast_model": "z-ai/glm-4.7-flash", # fast tier — JSON-only work, ~7x cheaper
    "offline_base_url": os.getenv("TAILSCALE_URL", ""),
    "offline_model": "qwen3:4b",               # fallback when credits run out
}


class ModelSettingsUpdate(BaseModel):
    mode: Optional[Literal["online", "offline"]] = None
    online_model: Optional[str] = None
    online_fast_model: Optional[str] = None
    offline_base_url: Optional[str] = None
    offline_model: Optional[str] = None


class ModelSettingsResponse(BaseModel):
    mode: Literal["online", "offline"]
    online_model: str
    online_fast_model: str
    offline_base_url: str
    offline_model: str


router = APIRouter(prefix="/settings", tags=["settings"])


@router.get("/model", response_model=ModelSettingsResponse)
async def get_model_settings() -> ModelSettingsResponse:
    return ModelSettingsResponse(**_model_settings)


@router.put("/model", response_model=ModelSettingsResponse)
async def update_model_settings(body: ModelSettingsUpdate) -> ModelSettingsResponse:
    _model_settings.update(body.model_dump(exclude_none=True))
    return ModelSettingsResponse(**_model_settings)


@router.get("/models")
async def list_openrouter_models():
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                "https://openrouter.ai/api/v1/models",
                headers={"Authorization": f"Bearer {_OPENROUTER_API_KEY}"},
            )
            r.raise_for_status()
            data = r.json()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"OpenRouter unreachable: {exc}")

    models = [
        {"id": m["id"], "name": m.get("name") or m["id"]}
        for m in data.get("data", [])
    ]
    models.sort(key=lambda m: m["name"].lower())
    return models
