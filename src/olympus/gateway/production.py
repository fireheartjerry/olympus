# ruff: noqa: E501

import base64
import binascii
import json
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Protocol

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.base import RequestResponseEndpoint

from olympus.authority.repository import AuthorityLease
from olympus.discord.contracts import DiscordInteraction
from olympus.discord.service import DiscordCommandResponse
from olympus.discord.verify import DiscordVerificationError, verify_discord_request
from olympus.webauthn.service import (
    AuthenticationAnomaly,
    BootstrapDenied,
    Ceremony,
    CeremonyPurpose,
    RecoveryCeremony,
    RecoveryResult,
)

MAX_REQUEST_BYTES = 1024 * 1024


class WebAuthnBoundary(Protocol):
    async def begin_registration(
        self,
        *,
        purpose: CeremonyPurpose,
        bootstrap_enabled: bool,
        now: datetime,
    ) -> Ceremony: ...

    async def finish_registration(
        self,
        *,
        challenge_id: str,
        response: dict[str, object],
        now: datetime,
    ) -> object: ...

    async def begin_authentication(self, *, now: datetime) -> Ceremony: ...

    async def finish_authentication(
        self,
        *,
        challenge_id: str,
        credential_id: bytes,
        response: dict[str, object],
        now: datetime,
    ) -> AuthorityLease: ...

    async def begin_recovery(
        self,
        *,
        request_id: str,
        credential_id: bytes,
        now: datetime,
    ) -> RecoveryCeremony: ...

    async def finish_recovery(
        self,
        *,
        challenge_id: str,
        credential_id: bytes,
        response: dict[str, object],
        now: datetime,
    ) -> RecoveryResult: ...


class DiscordBoundary(Protocol):
    async def handle(
        self,
        interaction: DiscordInteraction,
        *,
        raw_body: bytes,
        now: datetime,
    ) -> DiscordCommandResponse: ...


class EmptyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class VerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challenge_id: str = Field(min_length=1, max_length=128)
    credential: dict[str, object]


class RecoveryOptionsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(min_length=1, max_length=128)
    credential_id: str = Field(min_length=1, max_length=2048)


def create_production_app(
    *,
    webauthn: WebAuthnBoundary,
    discord: DiscordBoundary,
    discord_public_key: bytes,
    webauthn_origin: str,
    webauthn_host: str,
    bootstrap_enabled: bool,
    now: Callable[[], datetime],
    ready: Callable[[], bool],
) -> FastAPI:
    app = FastAPI(
        title="Olympus Authority",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.middleware("http")
    async def enforce_request_size(
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > MAX_REQUEST_BYTES:
                    return JSONResponse(
                        {"detail": "request too large"},
                        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    )
            except ValueError:
                return JSONResponse(
                    {"detail": "invalid content length"},
                    status_code=status.HTTP_400_BAD_REQUEST,
                )
        body = await request.body()
        if len(body) > MAX_REQUEST_BYTES:
            return JSONResponse(
                {"detail": "request too large"},
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            )
        return await call_next(request)

    @app.exception_handler(BootstrapDenied)
    async def bootstrap_denied(request: Request, exc: BootstrapDenied) -> JSONResponse:
        """A refused ceremony is a decision, not a crash.

        Bootstrap is denied on every request once a credential exists, so this
        is the *normal* steady state after enrollment rather than an edge case.
        Letting it surface as a 500 would bury a deliberate authority decision
        in what looks like a malfunction, and would make a real malfunction
        indistinguishable from correct operation in the logs.

        The reason is deliberately not echoed: the caller learns that the
        ceremony is unavailable, not whether that is because bootstrap is
        switched off or because a credential already exists.
        """
        return JSONResponse(
            {"detail": "ceremony unavailable"}, status_code=status.HTTP_403_FORBIDDEN
        )

    @app.exception_handler(AuthenticationAnomaly)
    async def authentication_anomaly(request: Request, exc: AuthenticationAnomaly) -> JSONResponse:
        # Anomalies are recorded by the authority service; the caller is told
        # only that it was refused.
        return JSONResponse({"detail": "request denied"}, status_code=status.HTTP_403_FORBIDDEN)

    def require_private_origin(request: Request) -> None:
        if (
            request.headers.get("origin") != webauthn_origin
            or request.headers.get("host") != webauthn_host
            or "x-forwarded-host" in request.headers
            or "x-forwarded-proto" in request.headers
        ):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="request denied")

    @app.get("/", response_class=HTMLResponse)
    async def mobile_page(request: Request) -> str:
        if request.headers.get("host") != webauthn_host:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="request denied")
        return _MOBILE_PAGE

    @app.get("/health/live")
    async def health_live() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health/ready")
    async def health_ready() -> JSONResponse:
        if not ready():
            return JSONResponse({"status": "unavailable"}, status_code=503)
        return JSONResponse({"status": "ready"})

    @app.post("/v1/webauthn/register/options")
    async def registration_options(request: Request, body: EmptyRequest) -> dict[str, object]:
        require_private_origin(request)
        ceremony = await webauthn.begin_registration(
            purpose=CeremonyPurpose.BOOTSTRAP_REGISTRATION,
            bootstrap_enabled=bootstrap_enabled,
            now=now(),
        )
        return {"challenge_id": ceremony.challenge_id, "options": ceremony.options}

    @app.post("/v1/webauthn/register/verify")
    async def registration_verify(
        request: Request,
        body: VerificationRequest,
    ) -> dict[str, str]:
        require_private_origin(request)
        await webauthn.finish_registration(
            challenge_id=body.challenge_id,
            response=body.credential,
            now=now(),
        )
        return {"status": "registered"}

    @app.post("/v1/webauthn/lease/options")
    async def lease_options(request: Request, body: EmptyRequest) -> dict[str, object]:
        require_private_origin(request)
        ceremony = await webauthn.begin_authentication(now=now())
        return {"challenge_id": ceremony.challenge_id, "options": ceremony.options}

    @app.post("/v1/webauthn/lease/verify")
    async def lease_verify(
        request: Request,
        body: VerificationRequest,
    ) -> dict[str, object]:
        require_private_origin(request)
        lease = await webauthn.finish_authentication(
            challenge_id=body.challenge_id,
            credential_id=_credential_id(body.credential),
            response=body.credential,
            now=now(),
        )
        return {
            "status": "authorized",
            "authority_epoch": lease.authority_epoch,
            "expires_at": lease.expires_at.isoformat(),
        }

    @app.post("/v1/webauthn/recovery/options")
    async def recovery_options(
        request: Request,
        body: RecoveryOptionsRequest,
    ) -> dict[str, object]:
        require_private_origin(request)
        recovery = await webauthn.begin_recovery(
            request_id=body.request_id,
            credential_id=_base64url_decode(body.credential_id),
            now=now(),
        )
        return {
            "challenge_id": recovery.ceremony.challenge_id,
            "options": recovery.ceremony.options,
            "payload": jsonable_encoder(recovery.payload),
        }

    @app.post("/v1/webauthn/recovery/verify")
    async def recovery_verify(
        request: Request,
        body: VerificationRequest,
    ) -> dict[str, object]:
        require_private_origin(request)
        result = await webauthn.finish_recovery(
            challenge_id=body.challenge_id,
            credential_id=_credential_id(body.credential),
            response=body.credential,
            now=now(),
        )
        return {
            "status": "recovered",
            "authority_epoch": result.lease.authority_epoch,
            "freeze_epoch": result.proof.freeze_epoch,
            "expires_at": result.lease.expires_at.isoformat(),
        }

    @app.post("/v1/discord/interactions")
    async def discord_interaction(request: Request) -> JSONResponse:
        raw_body = await request.body()
        try:
            verify_discord_request(
                raw_body=raw_body,
                signature_values=request.headers.getlist("x-signature-ed25519"),
                timestamp_values=request.headers.getlist("x-signature-timestamp"),
                public_key=discord_public_key,
                now=now(),
                tolerance=timedelta(minutes=5),
            )
            payload = json.loads(raw_body)
            interaction = DiscordInteraction.model_validate(payload)
            response = await discord.handle(interaction, raw_body=raw_body, now=now())
        except (DiscordVerificationError, ValueError, TypeError, json.JSONDecodeError):
            return JSONResponse({"detail": "request denied"}, status_code=401)
        return JSONResponse(jsonable_encoder(response))

    return app


def _credential_id(credential: dict[str, object]) -> bytes:
    raw_id = credential.get("rawId")
    if not isinstance(raw_id, str):
        raise HTTPException(status_code=422, detail="invalid credential")
    return _base64url_decode(raw_id)


def _base64url_decode(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))
    except (ValueError, binascii.Error) as exc:
        raise HTTPException(status_code=422, detail="invalid credential") from exc


_MOBILE_PAGE = """<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Olympus Authority</title>
<style>
body{font:16px system-ui;background:#090b10;color:#f6f7fb;max-width:34rem;margin:0 auto;padding:3rem 1.25rem}
h1{font-size:2rem}button{display:block;width:100%;padding:1rem;margin:1rem 0;border:0;border-radius:.8rem;
background:#6d5dfc;color:white;font-weight:700;font-size:1rem}button:active{transform:scale(.99)}
#status{padding:1rem;background:#151925;border-radius:.8rem;min-height:1.5rem}
</style>
<h1>Olympus Authority</h1>
<p>Face ID grants one bounded authority epoch. Discord messages cannot grant authority.</p>
<button onclick="register()">Register Face ID</button>
<button onclick="authorize()">Authorize for 24 hours</button>
<button onclick="recover()">Recover and unfreeze</button>
<div id="status">Ready.</div>
<script>
const statusBox=document.querySelector('#status');
const b64ToBuf=s=>{const v=s.replace(/-/g,'+').replace(/_/g,'/');const p=v+'='.repeat((4-v.length%4)%4);
return Uint8Array.from(atob(p),c=>c.charCodeAt(0))};
const bufToB64=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
function decode(o){o.challenge=b64ToBuf(o.challenge);if(o.user)o.user.id=b64ToBuf(o.user.id);
for(const k of ['excludeCredentials','allowCredentials'])if(o[k])o[k].forEach(x=>x.id=b64ToBuf(x.id));return o}
function encode(c){const r=c.response;const response={clientDataJSON:bufToB64(r.clientDataJSON)};
if(r.attestationObject)response.attestationObject=bufToB64(r.attestationObject);
if(r.authenticatorData)response.authenticatorData=bufToB64(r.authenticatorData);
if(r.signature)response.signature=bufToB64(r.signature);
if(r.userHandle)response.userHandle=bufToB64(r.userHandle);
return {id:c.id,rawId:bufToB64(c.rawId),type:c.type,response,
clientExtensionResults:c.getClientExtensionResults()}}
async function post(path,body={}){const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify(body)});if(!r.ok)throw new Error('Request denied');return r.json()}
async function ceremony(kind,extra={}){const start=await post(`/v1/webauthn/${kind}/options`,extra);
const publicKey=decode(start.options);const c=kind==='register'?await navigator.credentials.create({publicKey}):
await navigator.credentials.get({publicKey});localStorage.setItem('olympusCredentialId',bufToB64(c.rawId));
return post(`/v1/webauthn/${kind}/verify`,{challenge_id:start.challenge_id,credential:encode(c)})}
async function run(fn){try{statusBox.textContent='Waiting for Face ID…';const r=await fn();
statusBox.textContent=JSON.stringify(r)}catch(e){statusBox.textContent=e.message}}
const register=()=>run(()=>ceremony('register'));const authorize=()=>run(()=>ceremony('lease'));
const recover=()=>run(()=>ceremony('recovery',{request_id:crypto.randomUUID(),
credential_id:localStorage.getItem('olympusCredentialId')||''}));
</script>
</html>"""
