import json
from dataclasses import dataclass
from typing import Protocol

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from olympus.authority.repository import Credential


@dataclass(frozen=True)
class RegistrationRequest:
    rp_id: str
    rp_name: str
    commander_id: str
    challenge: bytes
    exclude_credentials: tuple[bytes, ...]


@dataclass(frozen=True)
class AuthenticationRequest:
    rp_id: str
    challenge: bytes
    allow_credentials: tuple[bytes, ...]


@dataclass(frozen=True)
class VerifiedRegistration:
    credential_id: bytes
    public_key: bytes
    sign_count: int


@dataclass(frozen=True)
class VerifiedAuthentication:
    credential_id: bytes
    new_sign_count: int


class WebAuthnBackend(Protocol):
    def registration_options(self, request: RegistrationRequest) -> dict[str, object]: ...

    def verify_registration(
        self,
        *,
        response: dict[str, object],
        expected_challenge: bytes,
        expected_rp_id: str,
        expected_origin: str,
    ) -> VerifiedRegistration: ...

    def authentication_options(self, request: AuthenticationRequest) -> dict[str, object]: ...

    def verify_authentication(
        self,
        *,
        response: dict[str, object],
        expected_challenge: bytes,
        expected_rp_id: str,
        expected_origin: str,
        credential: Credential,
    ) -> VerifiedAuthentication: ...


class PyWebAuthnBackend:
    def registration_options(self, request: RegistrationRequest) -> dict[str, object]:
        options = generate_registration_options(
            rp_id=request.rp_id,
            rp_name=request.rp_name,
            user_name=request.commander_id,
            user_id=request.commander_id.encode(),
            user_display_name="Jerry",
            challenge=request.challenge,
            timeout=300_000,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            exclude_credentials=[
                PublicKeyCredentialDescriptor(id=credential_id)
                for credential_id in request.exclude_credentials
            ],
            supported_pub_key_algs=[
                COSEAlgorithmIdentifier.ECDSA_SHA_256,
                COSEAlgorithmIdentifier.EDDSA,
            ],
        )
        return _json_options(options_to_json(options))

    def verify_registration(
        self,
        *,
        response: dict[str, object],
        expected_challenge: bytes,
        expected_rp_id: str,
        expected_origin: str,
    ) -> VerifiedRegistration:
        verified = verify_registration_response(
            credential=response,
            expected_challenge=expected_challenge,
            expected_rp_id=expected_rp_id,
            expected_origin=expected_origin,
            require_user_presence=True,
            require_user_verification=True,
            supported_pub_key_algs=[
                COSEAlgorithmIdentifier.ECDSA_SHA_256,
                COSEAlgorithmIdentifier.EDDSA,
            ],
        )
        if not verified.user_verified:
            raise ValueError("WebAuthn registration did not verify the user")
        return VerifiedRegistration(
            credential_id=verified.credential_id,
            public_key=verified.credential_public_key,
            sign_count=verified.sign_count,
        )

    def authentication_options(self, request: AuthenticationRequest) -> dict[str, object]:
        options = generate_authentication_options(
            rp_id=request.rp_id,
            challenge=request.challenge,
            timeout=300_000,
            allow_credentials=[
                PublicKeyCredentialDescriptor(id=credential_id)
                for credential_id in request.allow_credentials
            ],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        return _json_options(options_to_json(options))

    def verify_authentication(
        self,
        *,
        response: dict[str, object],
        expected_challenge: bytes,
        expected_rp_id: str,
        expected_origin: str,
        credential: Credential,
    ) -> VerifiedAuthentication:
        verified = verify_authentication_response(
            credential=response,
            expected_challenge=expected_challenge,
            expected_rp_id=expected_rp_id,
            expected_origin=expected_origin,
            credential_public_key=credential.public_key,
            credential_current_sign_count=credential.sign_count,
            require_user_verification=True,
        )
        if not verified.user_verified:
            raise ValueError("WebAuthn authentication did not verify the user")
        return VerifiedAuthentication(
            credential_id=verified.credential_id,
            new_sign_count=verified.new_sign_count,
        )


def _json_options(value: str) -> dict[str, object]:
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise TypeError("WebAuthn options must serialize to an object")
    return parsed
