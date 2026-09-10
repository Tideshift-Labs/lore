# Copyright 2026 Khurram Virani
# SPDX-License-Identifier: MIT
"""Owned signed CLI credentials for ordinary Python gRPC tests.

This local-store fixture does not advertise or prove domain receipt recovery.
The governed PostgreSQL proof remains clean_init_actual_cli.rs.
"""

import base64
from collections import deque
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
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from protobuf_wire import encode_bytes_field as field, parse_fields, _encode_varint


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


class ManagedAuth:
    def __init__(self, directory):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.identities = {}
        self.lock = threading.Lock()
        self.denied_exchanges = deque(maxlen=128)
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
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "Python fixture CA")]
        )
        ca = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    False, False, False, False, False, True, True, None, None
                ),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(ca_name)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
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
            .sign(ca_key, hashes.SHA256())
        )
        pem = cert.public_bytes(serialization.Encoding.PEM)
        self.server_certificate = cert
        self.ca_path = Path(directory) / "fixture-ca.pem"
        self.ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
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
                        "LookupUserPermissions": grpc.unary_unary_rpc_method_handler(
                            self.lookup_permissions
                        ),
                    },
                ),
                grpc.method_handlers_generic_handler(
                    "ucs.auth.RebacApi",
                    {
                        "CreateResource": grpc.unary_unary_rpc_method_handler(
                            self.create_resource
                        ),
                        "DeleteResource": grpc.unary_unary_rpc_method_handler(
                            self.delete_resource
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
                {"resource_id": r, "permission": list(permissions)}
                for r, permissions in resources.items()
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
            self.identities[token] = (subject, {})
        return token

    def grant(self, token, repository, *, admin=False):
        resource = "urc-" + uuid.UUID(repository).hex
        with self.lock:
            self.identities[token][1][resource] = (
                ("read", "write", "admin") if admin else ("read", "write")
            )

    def subject(self, token):
        with self.lock:
            return self.identities[token][0]

    def configure_server(self, server_root, env):
        env["SSL_CERT_FILE"] = str(self.ca_path)
        env.pop("SSL_CERT_DIR", None)
        config = Path(server_root) / "lore-server" / "config" / "local.toml"
        existing = config.read_text(encoding="utf-8") if config.exists() else ""
        if "[server.auth]" in existing or "[environment.endpoint]" in existing:
            raise RuntimeError("Fixture auth configuration already exists")
        config.write_text(
            existing + "\n[server.auth]\n"
            f"jwt_issuer={json.dumps(self.issuer)}\n"
            'jwt_audience=["lore-storage","commit0-cli","localhost","127.0.0.1"]\n'
            "enforce_write_permission=true\n[server.auth.jwk]\n"
            f"endpoint={json.dumps(self.jwks_url)}\n"
            "[environment.endpoint]\n"
            f"auth_url={json.dumps(self.url)}\n",
            encoding="utf-8",
        )

    def exchange_token(self, token, resources):
        # Use the actual TLS exchange; never expose credential-bearing RPC exceptions.
        endpoint = self.url.removeprefix("https://")
        credentials = grpc.ssl_channel_credentials(self.ca_path.read_bytes())
        try:
            with grpc.secure_channel(endpoint, credentials) as channel:
                call = channel.unary_unary(
                    "/epic_urc.UrcAuthApi/ExchangeUserTokenForMultiresourceToken"
                )
                response = call(
                    b"".join(field(1, resource.encode()) for resource in resources),
                    metadata=(("authorization", "Bearer " + token),),
                    timeout=10,
                )
            user = parse_fields(response).get(1, [])
            encoded = parse_fields(user[0]).get(1, []) if len(user) == 1 else []
            if len(encoded) != 1 or not isinstance(encoded[0], bytes):
                raise RuntimeError("Invalid fixture exchange response")
            return encoded[0].decode()
        except grpc.RpcError as error:
            raise RuntimeError(
                f"Fixture token exchange refused ({error.code().name}); credentials withheld"
            ) from None

    def authorized(self, context):
        bearer = dict(context.invocation_metadata()).get("authorization", "")
        with self.lock:
            identity = (
                self.identities.get(bearer.removeprefix("Bearer "))
                if bearer.startswith("Bearer ")
                else None
            )
            if identity:
                return identity[0], dict(identity[1])
        context.abort(grpc.StatusCode.UNAUTHENTICATED, "Unknown fixture identity")

    def exchange(self, request, context):
        subject, allowed = self.authorized(context)
        resources = [r.decode() for r in parse_fields(request).get(1, [])]
        if (
            not resources
            or len(set(resources)) != len(resources)
            or not set(resources) <= allowed.keys()
        ):
            with self.lock:
                self.denied_exchanges.append((subject, tuple(resources)))
            context.abort(
                grpc.StatusCode.PERMISSION_DENIED,
                "Repository is not granted to this fixture",
            )
        token = self.sign(
            subject, {resource: allowed[resource] for resource in resources}
        )
        user = (
            field(1, token.encode())
            + _encode_varint(2 << 3)
            + _encode_varint((int(time.time()) + 86400) * 1000)
            + field(3, subject.encode())
            + field(4, b"Python fixture")
        )
        return field(1, user)

    def create_resource(self, request, context):
        # Legacy create only: never acknowledge an attached governed claim.
        # The exact bearer lookup identifies a fixture-minted signed subject;
        # only that subject's preallocated repository may be registered.
        _, allowed = self.authorized(context)
        values = parse_fields(request)
        if (
            set(values) != {1, 2}
            or len(values[1]) != 1
            or len(values[2]) != 1
            or not isinstance(values[1][0], bytes)
            or not isinstance(values[2][0], bytes)
            or not values[2][0]
            or values[1][0].decode() not in allowed
        ):
            context.abort(
                grpc.StatusCode.PERMISSION_DENIED, "Create is outside the fixture grant"
            )
        return b""

    def delete_resource(self, request, context):
        subject, allowed = self.authorized(context)
        values = parse_fields(request)
        resources = values.get(1, [])
        if (
            set(values) != {1}
            or len(resources) != 1
            or not isinstance(resources[0], bytes)
            or resources[0].decode() not in allowed
        ):
            context.abort(
                grpc.StatusCode.PERMISSION_DENIED, "Delete is outside the fixture grant"
            )
        resource = resources[0].decode()
        bearer = dict(context.invocation_metadata())["authorization"].removeprefix(
            "Bearer "
        )
        with self.lock:
            identity = self.identities.get(bearer)
            if not identity or identity[0] != subject or resource not in identity[1]:
                context.abort(
                    grpc.StatusCode.PERMISSION_DENIED, "Fixture grant no longer exists"
                )
            del identity[1][resource]
        return b""

    def lookup_permissions(self, request, context):
        _, allowed = self.authorized(context)
        values = parse_fields(request)
        if values != {1: [b"urc"]}:
            context.abort(
                grpc.StatusCode.PERMISSION_DENIED,
                "Unsupported fixture permission lookup",
            )
        return b"".join(
            field(
                1,
                field(1, resource.encode())
                + b"".join(field(2, permission.encode()) for permission in permissions),
            )
            for resource, permissions in sorted(allowed.items())
        )

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
                permission += b"".join(
                    field(2, value.encode()) for value in allowed[resource.decode()]
                )
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
