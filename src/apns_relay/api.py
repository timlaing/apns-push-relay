"""v1 API routes (enrollment-spec v1.0, PLAN §3.2).

Handler order follows the spec's error matrix: per-IP rate limit → request
shape (FastAPI validation) → identity (tenant token + Ed25519 signature +
single-use nonce) → grant → quota → APNs. Push outcomes are always HTTP 200
with the result vocabulary; structured failures are stable machine codes.

Topic, environment and the grant-issuer key are never caller supplied — they
resolve from operator config and the stored challenge respectively.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
import time
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Request

from .attest import (
    AAGUID_BY_ATTEST_ENV,
    AttestError,
    load_attest_root,
    verify_assertion,
    verify_attestation,
)
from .callback import (
    CallbackError,
    callback_host_matches_id,
    validate_callback_url,
    verify_callback,
)
from .config import AppKeyConfig
from .errors import (
    ApiError,
    BadRequest,
    Conflict,
    Forbidden,
    TooManyRequests,
    Unauthorized,
    Unprocessable,
)
from .grants import (
    GrantError,
    grant_topic,
    issue_grant,
    parse_grant,
    sha256_token,
    verify_grant_for_push,
)
from .models import (
    EnrollBeginRequest,
    EnrollBeginResponse,
    EnrollFinishRequest,
    EnrollFinishResponse,
    EnrollRenewRequest,
    EnrollRenewResponse,
    PushRequest,
    PushResponse,
    RegisterRequest,
    RegisterResponse,
    RevokeRequest,
    RevokeResponse,
)
from .payload import PayloadError, build_payload, priority_for
from .ratelimit import ENROLL_LIMIT, REGISTER_LIMIT, client_ip
from .signing import (
    mint_tenant_token,
    public_key_from_b64,
    sha256hex,
    token_digest,
    verify,
)
from .store import TENANT_TTL, Tenant

if TYPE_CHECKING:
    from .app import AppState

# APNs `apns-push-type` header values (case-sensitive per Apple).
PUSH_TYPE = {
    "alert": "alert",
    "background": "background",
    "liveActivity": "liveactivity",
}

# Full claim set of a grant issued by this relay (spec §2.3). Renewal and
# revocation index claims directly, so completeness is asserted first.
FULL_GRANT_CLAIMS = (
    "jti",
    "iss",
    "tok",
    "ten",
    "tpk",
    "app",
    "kinds",
    "env",
    "iat",
    "exp",
    "ttl",
)


@dataclass(frozen=True)
class AuthContext:
    """Result of tenant authentication for one signed request."""

    tenant: Tenant
    raw: bytes


def blind_index(master_secret: bytes, destination_token: str) -> str:
    """Keyed blind index of a destination token — the only form at rest.

    HMAC-SHA256 with the operator's ``RELAY_MASTER_SECRET``; without the
    secret the index is unlinkable to the raw token, and the plaintext token
    is never written to disk or logs (PLAN §2).
    """
    digest = hmac.new(master_secret, destination_token.encode(), hashlib.sha256)
    return digest.hexdigest()[:32]


def _map_grant_error(exc: GrantError) -> ApiError:
    """Malformed/unverifiable grants are the caller's fault (400
    ``invalid_grant``); well-formed grants failing a policy check are 403."""
    if exc.code in ("malformed_grant", "bad_signature"):
        return BadRequest("invalid_grant")
    return Forbidden(exc.code)


def _require_full_grant(claims: dict) -> None:
    if not all(key in claims for key in FULL_GRANT_CLAIMS):
        raise GrantError("malformed_grant")


def _decode_b64(value: str, code: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise BadRequest(code) from None


def v1_router(state: AppState) -> APIRouter:
    router = APIRouter(prefix="/v1", tags=["v1"])

    # -- tenant authentication (spec §2.4) -----------------------------------

    async def authenticate(request: Request) -> AuthContext:
        """Token → tenant lookup → Ed25519 signature → single-use nonce →
        ``last_seen`` touch. Raises ``Unauthorized`` with a precise code."""
        raw = await request.body()
        header = request.headers.get("authorization", "")
        if not header.startswith("Bearer "):
            raise Unauthorized("missing_token")
        token = header[len("Bearer ") :]
        tenant = state.store.tenant_by_token(token_digest(token))
        if tenant is None:
            raise Unauthorized("unknown_tenant")
        if not tenant.pubkey:
            # Registered but never enrolled: nothing to verify signatures with.
            raise Unauthorized("enrollment_required")
        timestamp = request.headers.get("x-relay-time")
        if timestamp is None:
            raise Unauthorized("invalid_timestamp")
        nonce = request.headers.get("x-relay-nonce")
        if nonce is None or not (8 <= len(nonce) <= 128):
            raise Unauthorized("invalid_nonce")
        signature = request.headers.get("x-relay-signature")
        if signature is None:
            raise Unauthorized("invalid_signature")
        now = time.time()
        failure = verify(
            public_key_from_b64(tenant.pubkey),
            token,
            request.method,
            request.url.path,
            timestamp,
            nonce,
            raw,
            signature,
            now=now,
        )
        if failure is not None:
            raise Unauthorized(failure)
        if not state.store.claim_nonce(sha256hex(nonce.encode()), now):
            raise Unauthorized("replayed_nonce")
        state.store.touch(tenant.id, now)
        return AuthContext(tenant=tenant, raw=raw)

    def app_or_400(app_id: str) -> AppKeyConfig:
        try:
            app = state.config.app(app_id)
        except KeyError:
            raise BadRequest("unknown_app") from None
        if not app.enabled:
            # Disabled Apps are indistinguishable from unknown ones on
            # unauthenticated routes (no config-state disclosure).
            raise BadRequest("unknown_app")
        return app

    def app_for_tenant(tenant: Tenant) -> AppKeyConfig:
        try:
            app = state.config.app(tenant.app)
        except KeyError:
            raise Forbidden("app_disabled") from None
        if not app.enabled:
            raise Forbidden("app_disabled")
        return app

    # -- POST /v1/register (PLAN §3.1) ---------------------------------------

    @router.post("/register", status_code=201, response_model=RegisterResponse)
    async def register(request: Request, body: RegisterRequest) -> RegisterResponse:
        now = time.time()
        ip = client_ip(request)
        if not state.limiter.allow(f"register|{ip}", REGISTER_LIMIT[0], REGISTER_LIMIT[1], now):
            raise TooManyRequests("rate_limited")
        app = app_or_400(body.app)
        if app.registration.callback_required and not body.callback:
            raise BadRequest("callback_required")
        if body.callback is not None:
            # Ownership proof: PublicHTTPS callback (callback.py), inline,
            # 201 only on success (PLAN §3.1 matrix).
            try:
                url = validate_callback_url(body.callback)
            except CallbackError:
                raise BadRequest("invalid_callback") from None
            host = urlsplit(url).hostname or ""
            if not callback_host_matches_id(host, body.id):
                raise BadRequest("invalid_callback")
            nonce = secrets.token_urlsafe(32)
            try:
                verified = await verify_callback(url, body.id, nonce, client=state.callback_client)
            except CallbackError:
                raise BadRequest("invalid_callback") from None
            if not verified:
                raise BadRequest("callback_verification_failed")
        token = mint_tenant_token()
        if not state.store.register_tenant(body.id, body.app, token_digest(token), now):
            raise Conflict("id_exists")
        state.metrics.inc("registers_total", "ok")
        return RegisterResponse(
            tenant=body.id,
            app=body.app,
            token=token,
            quota={
                "burst_per_min": app.quota.burst_per_min,
                "daily": app.quota.daily,
                "token_burst_per_min": app.quota.token_burst_per_min,
            },
            registered_at=int(now),
            expires_at=int(now) + TENANT_TTL,
        )

    # -- POST /v1/enroll/begin (spec §2.1) -----------------------------------

    @router.post("/enroll/begin", response_model=EnrollBeginResponse)
    async def enroll_begin(request: Request, body: EnrollBeginRequest) -> EnrollBeginResponse:
        now = time.time()
        if not state.limiter.allow(
            f"enroll|{client_ip(request)}", ENROLL_LIMIT[0], ENROLL_LIMIT[1], now
        ):
            raise TooManyRequests("rate_limited")
        app = app_or_400(body.app)
        tenant = state.store.tenant(body.tenantId, body.app)
        if tenant is None:
            raise BadRequest("unknown_tenant")
        challenge_id = str(uuid.uuid4())
        nonce = secrets.token_urlsafe(32)
        server_challenge = secrets.token_urlsafe(32)
        expires_at = now + state.config.enrollment.challenge_ttl
        challenge_payload = {
            "aps": {"content-available": 1},
            "relay-challenge": {"id": challenge_id, "nonce": nonce},
        }
        # Silent challenge push. Devices are environment-bound, so try each
        # configured environment in order; an invalid-destination answer means
        # "wrong environment for this token" until the list is exhausted.
        failure_detail = "challenge_push_failed"
        chosen: str | None = None
        for environment in app.environments:
            result = await state.sender.send(
                app,
                device_token=body.destinationToken,
                topic=app.topic,
                environment=environment,
                payload=challenge_payload,
                push_type="background",
                priority=5,
                expiration=int(expires_at),
            )
            if result.outcome == "accepted":
                chosen = environment
                break
            failure_detail = result.reason or result.outcome
            if result.outcome != "invalidDestination":
                break  # network/throttle/APNs error: fail cleanly, retry later
        if chosen is None:
            # Spec §2.1: APNs rejected the token → 400, nothing stored.
            raise BadRequest("invalidDestination", detail=failure_detail)
        state.store.put_challenge(
            challenge_id,
            app.id,
            tenant.id,
            # Spec §2.3: `tok` is SHA-256 of the *destination* token — that is
            # what gets hashed into the grant (never the tenant token).
            sha256_token(body.destinationToken),
            nonce,
            server_challenge,
            chosen,
            expires_at,
        )
        state.metrics.inc("enrolls_total", "begin")
        return EnrollBeginResponse(
            challengeId=challenge_id,
            serverChallenge=server_challenge,
            expiresAt=int(expires_at),
        )

    # -- POST /v1/enroll/finish (spec §2.2) ----------------------------------

    @router.post("/enroll/finish", response_model=EnrollFinishResponse)
    async def enroll_finish(request: Request, body: EnrollFinishRequest) -> EnrollFinishResponse:
        now = time.time()
        if not state.limiter.allow(
            f"enroll|{client_ip(request)}", ENROLL_LIMIT[0], ENROLL_LIMIT[1], now
        ):
            raise TooManyRequests("rate_limited")
        # Single-use: popped (and burned) even when verification fails below.
        challenge, failure = state.store.pop_challenge(body.challengeId, now)
        if failure is not None:
            raise BadRequest(failure)  # unknown_challenge | challenge_expired
        if challenge.tenant_id != body.tenantId:
            raise BadRequest("challenge_tenant_mismatch")
        try:
            app = state.config.app(challenge.app)
        except KeyError:
            raise BadRequest("unknown_app") from None
        if not app.enabled:
            raise BadRequest("unknown_app")
        tenant = state.store.tenant(challenge.tenant_id, app.id)
        if tenant is None:
            raise BadRequest("unknown_tenant")
        # Attestation root is chosen from the App's attest_environment —
        # development and production chain to different Apple roots. The relay
        # fails closed when the operator has not supplied the root (M4).
        root_path = state.config.enrollment.root_for(app.attest_environment)
        if root_path is None:
            raise BadRequest("attestation_unavailable")
        try:
            root = load_attest_root(root_path)
        except (OSError, ValueError):
            raise BadRequest("attestation_unavailable") from None
        attestation_cbor = _decode_b64(body.attestation, "malformed_attestation")
        try:
            credential = verify_attestation(
                attestation_cbor,
                root=root,
                expected_rp_id=app.bundle_id,
                expected_aaguid=AAGUID_BY_ATTEST_ENV[app.attest_environment],
                nonce=challenge.nonce.encode(),
                server_challenge=challenge.server_challenge.encode(),
            )
        except AttestError as exc:
            raise BadRequest(exc.code) from None
        assertion_cbor = _decode_b64(body.assertion, "malformed_assertion")
        try:
            verify_assertion(
                assertion_cbor,
                credential=credential,
                nonce=challenge.nonce.encode(),
                server_challenge=challenge.server_challenge.encode(),
                expected_rp_id=app.bundle_id,
            )
        except AttestError as exc:
            raise BadRequest(exc.code) from None
        kinds = sorted({*body.kinds})
        for kind in kinds:
            if kind not in app.kinds:
                raise BadRequest("kinds_not_allowed")
        ttl = app.grant_ttl.clamp(body.ttl)
        try:
            public_key_from_b64(body.tenantPubkey)
        except ValueError:
            raise BadRequest("invalid_pubkey") from None
        # Trust-on-first-use (spec §2.4): the signing key is set exactly once.
        # enroll/finish is unauthenticated by design (App Attest proves the
        # device), so replacing a stored key here would let anyone holding a
        # stolen token enroll their own key and impersonate the tenant. Key
        # rotation is `relay tenant revoke` + re-enroll.
        if tenant.pubkey and tenant.pubkey != body.tenantPubkey:
            raise BadRequest("invalid_pubkey")
        if not tenant.pubkey and not state.store.set_pubkey(
            challenge.tenant_id, app.id, body.tenantPubkey
        ):
            raise BadRequest("invalid_pubkey")  # lost a first-enroll race
        grant = issue_grant(
            state.issuer_key,
            state.issuer_id,
            token_digest=challenge.token_digest,
            tenant_id=challenge.tenant_id,
            tenant_pubkey=body.tenantPubkey,
            app_id=app.id,
            kinds=kinds,
            environment=challenge.environment,
            ttl=ttl,
            now=now,
        )
        consent = {
            "tenant": challenge.tenant_id,
            "app": app.id,
            "appDisplayName": app.display_name,
            "kinds": kinds,
            "boundAt": int(now),
            "expiresAt": int(now) + ttl,
            "environment": challenge.environment,
        }
        state.metrics.inc("enrolls_total", "finish")
        return EnrollFinishResponse(grant=grant, consent=consent)

    # -- POST /v1/enroll/renew (spec §2.4) -----------------------------------

    @router.post("/enroll/renew", response_model=EnrollRenewResponse)
    async def enroll_renew(
        body: EnrollRenewRequest,
        ctx: AuthContext = Depends(authenticate),
    ) -> EnrollRenewResponse:
        now = time.time()
        app = app_for_tenant(ctx.tenant)
        try:
            claims = parse_grant(body.grant, state.issuer_public)
            _require_full_grant(claims)
        except GrantError as exc:
            raise _map_grant_error(exc) from None
        if claims["exp"] <= now:
            raise Forbidden("grant_expired")
        if state.store.is_denied([claims["jti"]], now):
            raise Forbidden("grant_revoked")
        if (
            claims["ten"] != ctx.tenant.id
            or claims["tpk"] != ctx.tenant.pubkey
            or claims["app"] != ctx.tenant.app
        ):
            raise Forbidden("grant_mismatch")
        ttl = app.grant_ttl.clamp(body.ttl)
        # New jti/iat/exp; every other claim unchanged (spec §2.4).
        renewal = issue_grant(
            state.issuer_key,
            state.issuer_id,
            token_digest=claims["tok"].removeprefix("sha256:"),
            tenant_id=claims["ten"],
            tenant_pubkey=claims["tpk"],
            app_id=claims["app"],
            kinds=list(claims["kinds"]),
            environment=claims["env"],
            ttl=ttl,
            now=now,
        )
        state.metrics.inc("enrolls_total", "renew")
        return EnrollRenewResponse(grant=renewal, expiresAt=int(now) + ttl)

    # -- POST /v1/revoke (PLAN §3.3) -----------------------------------------

    @router.post("/revoke", response_model=RevokeResponse)
    async def revoke(
        body: RevokeRequest,
        ctx: AuthContext = Depends(authenticate),
    ) -> RevokeResponse:
        now = time.time()
        try:
            claims = parse_grant(body.grant, state.issuer_public)
            _require_full_grant(claims)
        except GrantError as exc:
            raise _map_grant_error(exc) from None
        if (
            claims["ten"] != ctx.tenant.id
            or claims["tpk"] != ctx.tenant.pubkey
            or claims["app"] != ctx.tenant.app
        ):
            raise Forbidden("grant_mismatch")
        if claims["exp"] > now:
            # An already-expired grant needs no entry (is_denied purges
            # expired rows); revocation stays idempotent either way.
            state.store.deny(claims["jti"], float(claims["exp"]))
        state.metrics.inc("revocations_total", "ok")
        return RevokeResponse(revoked=claims["jti"])

    # -- POST /v1/push (PLAN §3.2, notifications.md contract) ----------------

    @router.post("/push", response_model=PushResponse)
    async def push(
        body: PushRequest,
        ctx: AuthContext = Depends(authenticate),
    ) -> PushResponse:
        now = time.time()
        app = app_for_tenant(ctx.tenant)
        try:
            claims = verify_grant_for_push(
                body.grant,
                state.issuer_public,
                app=app,
                destination_token_digest=sha256_token(body.destinationToken),
                tenant_id=ctx.tenant.id,
                tenant_pubkey=ctx.tenant.pubkey,
                kind=body.kind,
                now=now,
            )
        except GrantError as exc:
            raise _map_grant_error(exc) from None
        if body.kind not in app.kinds:
            raise Forbidden("kind_not_allowed")
        if claims.get("env") not in app.environments:
            raise Forbidden("environment_not_allowed")
        if state.store.is_denied([claims.get("jti", ""), claims.get("tok", "")], now):
            raise Forbidden("grant_revoked")
        try:
            payload = build_payload(body.kind, body.content.model_dump(exclude_none=True), app.caps)
        except PayloadError as exc:
            raise Unprocessable(exc.code, exc.detail or "") from None
        failure = state.store.check_and_record(
            ctx.tenant.id,
            ctx.tenant.app,
            blind_index(state.master_secret, body.destinationToken),
            now,
            burst_per_min=app.quota.burst_per_min,
            daily=app.quota.daily,
            token_burst_per_min=app.quota.token_burst_per_min,
        )
        if failure is not None:
            raise TooManyRequests(failure)  # rate_limited/token_rate_limited/quota_exhausted
        result = await state.sender.send(
            app,
            device_token=body.destinationToken,
            topic=grant_topic(app, body.kind),
            environment=claims["env"],
            payload=payload,
            push_type=PUSH_TYPE[body.kind],
            priority=priority_for(body.kind),
            expiration=body.expiresAt,
            collapse_id=body.eventId,
        )
        state.metrics.inc("pushes_total", result.outcome)
        return PushResponse(
            result=result.outcome,
            apnsId=result.apns_id or None,
            detail=result.reason or None,
        )

    return router
