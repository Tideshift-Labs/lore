# Copyright 2026 Khurram Virani
# SPDX-License-Identifier: MIT
"""Owned signed CLI credentials for ordinary Python gRPC tests.

This local-store fixture does not advertise or prove domain receipt recovery.
The governed PostgreSQL proof remains clean_init_actual_cli.rs.
"""

import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import threading
import time
import uuid

import grpc
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from protobuf_wire import encode_bytes_field as field, parse_fields, _encode_varint


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


class ManagedAuth:
    def __init__(self, directory):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.identities = {}
        self.lock = threading.Lock()
        self.issuer = "https://python-fixture.invalid/" + uuid.uuid4().hex
        self.executor = ThreadPoolExecutor(max_workers=4)
        public = self.key.public_key().public_numbers()
        jwks = json.dumps(
            {
                "keys": [
                    {
                        "kty": "RSA",
                        "alg": "RS256",
                        "use": "sig",
                        "kid": "python-fixture",
                        "n": b64(public.n.to_bytes(256, "big")),
                        "e": b64(public.e.to_bytes(3, "big")),
                    }
                ]
            }
        ).encode()

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path != "/jwks":
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(jwks)))
                self.end_headers()
                self.wfile.write(jwks)

            def log_message(self, *args):
                pass

        self.http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        now = datetime.now(timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("localhost"),
                        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    ]
                ),
                critical=False,
            )
            .sign(self.key, hashes.SHA256())
        )
        pem = cert.public_bytes(serialization.Encoding.PEM)
        self.ca_path = Path(directory) / "fixture-ca.pem"
        self.ca_path.write_bytes(pem)
        private = self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self.grpc = grpc.server(self.executor)
        self.grpc.add_generic_rpc_handlers(
            (
                grpc.method_handlers_generic_handler(
                    "epic_urc.UrcAuthApi",
                    {
                        "ExchangeUserTokenForMultiresourceToken": grpc.unary_unary_rpc_method_handler(
                            self.exchange
                        ),
                        "CheckUserPermission": grpc.unary_unary_rpc_method_handler(
                            self.permissions
                        ),
                    },
                ),
            )
        )
        port = self.grpc.add_secure_port(
            "127.0.0.1:0", grpc.ssl_server_credentials(((private, pem),))
        )
        if not port:
            raise RuntimeError("Could not bind owned auth service")
        self.url = f"https://localhost:{port}"
        self.jwks_url = f"http://127.0.0.1:{self.http.server_port}/jwks"
        self.thread.start()
        self.grpc.start()

    def close(self):
        self.grpc.stop(0).wait(5)
        self.executor.shutdown(wait=True)
        self.http.shutdown()
        self.http.server_close()
        self.thread.join(5)

    def sign(self, subject, resources=None):
        now = int(time.time())
        claims = {
            "sub": subject,
            "iss": self.issuer,
            "iat": now,
            "exp": now + 86400,
            "aud": [
                "lore-storage" if resources is not None else "commit0-cli",
                "localhost",
                "127.0.0.1",
            ],
            "name": "Python fixture",
            "preferred_username": "Python fixture",
            "is_service_account": False,
            "idp": "python-fixture",
            "env": "test",
            "groups": [],
        }
        if resources is not None:
            claims["resources"] = [
                {"resource_id": r, "permission": ["read", "write"]} for r in resources
            ]
        payload = ".".join(
            b64(json.dumps(v, separators=(",", ":")).encode())
            for v in ({"alg": "RS256", "kid": "python-fixture", "typ": "JWT"}, claims)
        )
        return (
            payload
            + "."
            + b64(self.key.sign(payload.encode(), padding.PKCS1v15(), hashes.SHA256()))
        )

    def identity(self):
        subject = str(uuid.uuid4())
        token = self.sign(subject)
        with self.lock:
            self.identities[token] = (subject, set())
        return token

    def grant(self, token, repository):
        resource = "urc-" + uuid.UUID(repository).hex
        with self.lock:
            self.identities[token][1].add(resource)

    def authorized(self, context):
        bearer = dict(context.invocation_metadata()).get("authorization", "")
        with self.lock:
            identity = (
                self.identities.get(bearer.removeprefix("Bearer "))
                if bearer.startswith("Bearer ")
                else None
            )
            if identity:
                return identity[0], set(identity[1])
        context.abort(grpc.StatusCode.UNAUTHENTICATED, "Unknown fixture identity")

    def exchange(self, request, context):
        subject, allowed = self.authorized(context)
        resources = [r.decode() for r in parse_fields(request).get(1, [])]
        if (
            not resources
            or len(set(resources)) != len(resources)
            or not set(resources) <= allowed
        ):
            context.abort(
                grpc.StatusCode.PERMISSION_DENIED,
                "Repository is not granted to this fixture",
            )
        token = self.sign(subject, resources)
        user = (
            field(1, token.encode())
            + _encode_varint(2 << 3)
            + _encode_varint((int(time.time()) + 86400) * 1000)
            + field(3, subject.encode())
            + field(4, b"Python fixture")
        )
        return field(1, user)

    def permissions(self, request, context):
        _, allowed = self.authorized(context)
        values = parse_fields(request)
        if 2 in values:
            context.abort(
                grpc.StatusCode.PERMISSION_DENIED, "Cannot impersonate another fixture"
            )
        result = b""
        for resource in values.get(1, []):
            granted = resource.decode() in allowed
            permission = field(1, resource)
            if granted:
                permission += field(2, b"read") + field(2, b"write")
            result += field(1 if granted else 2, permission)
        return result

    def login(self, executable, directory, remote, token):
        env = os.environ.copy()
        env.update(self.environment(directory))
        env.pop("SSL_CERT_DIR", None)
        # Never route bearer-bearing argv/output through Lore.run's diagnostics.
        try:
            result = subprocess.run(
                [
                    executable,
                    "auth",
                    "login",
                    remote,
                    "--token",
                    token,
                    "--token-type",
                    "lore",
                    "--auth-url",
                    self.url,
                ],
                cwd=directory,
                env=env,
                capture_output=True,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, OSError):
            # TimeoutExpired embeds the credential-bearing command in its text.
            raise RuntimeError(
                "Owned fixture login could not complete; credential output withheld"
            ) from None
        if result.returncode:
            raise RuntimeError(
                f"Owned fixture login failed (exit {result.returncode}); credential output withheld"
            )

    def environment(self, directory):
        return {
            "SSL_CERT_FILE": str(self.ca_path),
            "LORE_GLOBAL_PATH": str(directory),
            "LORE_AUTH_PATH": str(directory),
        }
