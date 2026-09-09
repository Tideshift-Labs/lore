# Copyright 2026 Khurram Virani
# SPDX-License-Identifier: MIT
"""Hermetic auth exchange checks; run with unittest to avoid native fixtures."""

import base64
import json
import tempfile
import subprocess
import unittest
import uuid
from unittest.mock import patch

import grpc
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from managed_auth import ManagedAuth
from protobuf_wire import encode_bytes_field as field, parse_fields


class ManagedAuthTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.auth = ManagedAuth(self.directory.name)
        self.channel = grpc.secure_channel(
            self.auth.url.removeprefix("https://"),
            grpc.ssl_channel_credentials(self.auth.ca_path.read_bytes()),
        )
        self.token = self.auth.identity()
        self.repository = uuid.uuid4().hex
        self.auth.grant(self.token, self.repository)

    def tearDown(self):
        self.channel.close()
        self.auth.close()
        self.directory.cleanup()

    def call(self, name, payload, token=None):
        rpc = self.channel.unary_unary("/epic_urc.UrcAuthApi/" + name)
        return rpc(
            payload,
            metadata=(("authorization", "Bearer " + (token or self.token)),),
            timeout=5,
        )

    def test_signed_exchange_exact_resource_and_subject(self):
        resource = "urc-" + self.repository
        result = self.call(
            "ExchangeUserTokenForMultiresourceToken", field(1, resource.encode())
        )
        user = parse_fields(parse_fields(result)[1][0])
        token = user[1][0].decode()
        self.assertNotEqual(token, self.token)
        header, payload, signature = token.split(".")

        def decode(s):
            return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

        self.auth.key.public_key().verify(
            decode(signature),
            (header + "." + payload).encode(),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        claims = json.loads(decode(payload))
        self.assertEqual(claims["iss"], self.auth.issuer)
        self.assertEqual(claims["sub"], user[3][0].decode())
        self.assertEqual(
            claims["resources"],
            [{"resource_id": resource, "permission": ["read", "write"]}],
        )
        with self.assertRaises(grpc.RpcError) as error:
            self.call(
                "ExchangeUserTokenForMultiresourceToken",
                field(1, resource.encode()),
                token,
            )
        self.assertEqual(error.exception.code(), grpc.StatusCode.UNAUTHENTICATED)

    def test_foreign_identity_resource_and_impersonation_refused(self):
        resource = field(1, ("urc-" + self.repository).encode())
        for request, token in (
            (resource, self.auth.identity()),
            (field(1, b"urc-00000000000000000000000000000000"), self.token),
        ):
            with self.assertRaises(grpc.RpcError) as error:
                self.call("ExchangeUserTokenForMultiresourceToken", request, token)
            self.assertEqual(error.exception.code(), grpc.StatusCode.PERMISSION_DENIED)
        result = parse_fields(
            self.call("CheckUserPermission", resource + field(1, b"foreign"))
        )
        self.assertEqual(len(result[1]), 1)
        self.assertEqual(parse_fields(result[2][0]), {1: [b"foreign"]})
        with self.assertRaises(grpc.RpcError) as error:
            self.call("CheckUserPermission", resource + field(2, b""))
        self.assertEqual(error.exception.code(), grpc.StatusCode.PERMISSION_DENIED)

    def test_login_failure_does_not_expose_bearer_or_output(self):
        with patch("managed_auth.subprocess.run") as run:
            run.return_value.returncode = 1
            run.return_value.stderr = self.token.encode()
            with self.assertRaises(RuntimeError) as error:
                self.auth.login(
                    "owned-cli",
                    self.directory.name,
                    "grpc://127.0.0.1:1234/",
                    self.token,
                )
            self.assertNotIn(self.token, str(error.exception))
            self.assertEqual(
                run.call_args.kwargs["env"]["LORE_AUTH_PATH"], self.directory.name
            )
            self.assertTrue(run.call_args.kwargs["capture_output"])
            run.side_effect = subprocess.TimeoutExpired(["cli", self.token], 30)
            with self.assertRaises(RuntimeError) as error:
                self.auth.login(
                    "owned-cli",
                    self.directory.name,
                    "grpc://127.0.0.1:1234/",
                    self.token,
                )
            self.assertNotIn(self.token, str(error.exception))


if __name__ == "__main__":
    unittest.main()
