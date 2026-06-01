"""Ground-station to satellite command routes."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from api.tcp_command_sender import TCPCommandSender

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/command", tags=["command"])


class ThresholdCommandRequest(BaseModel):
    sw_id: int = Field(..., ge=0, le=3)
    lo: float
    hi: float


class HashCommandRequest(BaseModel):
    file_id: int = Field(..., ge=0)
    file_path: str = Field(..., min_length=1)
    expected_hash: str = Field(..., min_length=1)


def _get_sender(request: Request) -> TCPCommandSender:
    try:
        sender = getattr(request.app.state, "command_sender", None)
        if sender is None:
            raise HTTPException(status_code=503, detail="command sender is not initialized")
        return sender
    except HTTPException:
        raise
    except Exception as error:
        logger.error("command sender lookup failed: %s", error)
        raise HTTPException(status_code=500, detail=str(error)) from error


@router.post("/attack_sim")
async def send_attack_sim(request: Request) -> dict[str, str]:
    try:
        sender = _get_sender(request)
        if await sender.send_attack_sim():
            return {"status": "sent", "cmd": "ATTACK_SIM"}
        return {"status": "failed", "reason": "command delivery failed"}
    except HTTPException:
        raise
    except Exception as error:
        logger.error("attack_sim command route failed: %s", error)
        raise HTTPException(status_code=500, detail=str(error)) from error


@router.post("/attack_hash")
async def send_attack_hash(request: Request) -> dict[str, str]:
    try:
        sender = _get_sender(request)
        if await sender.send_attack_hash():
            return {"status": "sent", "cmd": "ATTACK_HASH"}
        return {"status": "failed", "reason": "command delivery failed"}
    except HTTPException:
        raise
    except Exception as error:
        logger.error("attack_hash command route failed: %s", error)
        raise HTTPException(status_code=500, detail=str(error)) from error


@router.post("/recovery")
async def send_recovery(request: Request) -> dict[str, str]:
    try:
        sender = _get_sender(request)
        if await sender.send_recovery():
            return {"status": "sent", "cmd": "RECOVERY"}
        return {"status": "failed", "reason": "command delivery failed"}
    except HTTPException:
        raise
    except Exception as error:
        logger.error("recovery command route failed: %s", error)
        raise HTTPException(status_code=500, detail=str(error)) from error


@router.patch("/threshold")
async def send_threshold(request: Request, body: ThresholdCommandRequest) -> dict[str, str]:
    try:
        sender = _get_sender(request)
        if await sender.send_update_threshold(body.sw_id, body.lo, body.hi):
            return {"status": "sent", "cmd": "UPDATE_THRESHOLD"}
        return {"status": "failed", "reason": "command delivery failed"}
    except HTTPException:
        raise
    except Exception as error:
        logger.error("threshold command route failed: %s", error)
        raise HTTPException(status_code=500, detail=str(error)) from error


@router.patch("/hash")
async def send_hash(request: Request, body: HashCommandRequest) -> dict[str, str]:
    try:
        sender = _get_sender(request)
        if await sender.send_update_hash(body.file_id, body.file_path, body.expected_hash):
            return {"status": "sent", "cmd": "UPDATE_HASH"}
        return {"status": "failed", "reason": "command delivery failed"}
    except HTTPException:
        raise
    except Exception as error:
        logger.error("hash command route failed: %s", error)
        raise HTTPException(status_code=500, detail=str(error)) from error
