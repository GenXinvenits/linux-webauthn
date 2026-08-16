#!/usr/bin/env python3

import base64
import hashlib
import json
import os
import subprocess
import tempfile
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

HOST = "127.0.0.1"
PORT = 8080
ORIGIN = f"http://localhost:{PORT}"
RP_ID = "localhost"

# The test server keeps all registered credentials so that multiple
# discoverable credentials for the same RP can be exercised.
credentials = {}
pending_register = None
pending_authenticate = None


def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64u(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def json_bytes(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()


def fail(message):
    raise ValueError(message)


def parse_client_data(raw):
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception as exc:
        fail(f"invalid clientDataJSON: {exc}")


def verify_client_data(raw, expected_type, expected_challenge):
    data = parse_client_data(raw)
    if data.get("type") != expected_type:
        fail(f"clientData type mismatch: {data.get('type')!r}")
    if data.get("challenge") != b64u(expected_challenge):
        fail("clientData challenge mismatch")
    if data.get("origin") != ORIGIN:
        fail(f"clientData origin mismatch: {data.get('origin')!r}")


def verify_registration(body):
    global pending_register
    if pending_register is None:
        fail("no pending registration challenge")

    raw_id = unb64u(body["credentialId"])
    client_data = unb64u(body["clientDataJSON"])
    auth_data = unb64u(body["authenticatorData"])
    public_key_spki = unb64u(body["publicKey"])

    verify_client_data(client_data, "webauthn.create", pending_register)

    if len(auth_data) < 37:
        fail("authenticatorData is too short")

    if auth_data[:32] != hashlib.sha256(RP_ID.encode()).digest():
        fail("registration RP ID hash mismatch")

    flags = auth_data[32]
    if not (flags & 0x01):
        fail("registration UP flag missing")
    if not (flags & 0x04):
        fail("registration UV flag missing")
    if not (flags & 0x40):
        fail("registration AT flag missing")

    credential = {
        "id": raw_id,
        "public_key": public_key_spki,
        "counter": int.from_bytes(auth_data[33:37], "big"),
        "flags": flags,
    }
    credentials[b64u(raw_id)] = credential
    pending_register = None

    return {
        "ok": True,
        "message": "Registration verified",
        "credentialId": b64u(raw_id),
        "counter": credential["counter"],
        "storedCredentials": len(credentials),
    }


def verify_signature(public_key_spki, signature, signed_data):
    with tempfile.TemporaryDirectory(prefix="linux-webauthn-verify-") as td:
        key_path = os.path.join(td, "public.der")
        sig_path = os.path.join(td, "signature.der")
        data_path = os.path.join(td, "signed-data.bin")
        pem_path = os.path.join(td, "public.pem")

        open(key_path, "wb").write(public_key_spki)
        open(sig_path, "wb").write(signature)
        open(data_path, "wb").write(signed_data)

        r = subprocess.run(
            ["openssl", "pkey", "-pubin", "-inform", "DER", "-in", key_path,
             "-out", pem_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if r.returncode != 0:
            fail("stored public key is invalid")

        r = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", pem_path,
             "-signature", sig_path, data_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if r.returncode != 0 or r.stdout.strip() != "Verified OK":
            fail("WebAuthn signature verification failed")


def verify_authentication(body):
    global pending_authenticate
    if pending_authenticate is None:
        fail("no pending authentication challenge")

    raw_id = unb64u(body["credentialId"])
    client_data = unb64u(body["clientDataJSON"])
    auth_data = unb64u(body["authenticatorData"])
    signature = unb64u(body["signature"])

    credential = credentials.get(b64u(raw_id))
    if credential is None:
        fail("credential ID is not registered on the test server")

    verify_client_data(client_data, "webauthn.get", pending_authenticate)

    if len(auth_data) < 37:
        fail("authenticatorData is too short")
    if auth_data[:32] != hashlib.sha256(RP_ID.encode()).digest():
        fail("authentication RP ID hash mismatch")

    flags = auth_data[32]
    if not (flags & 0x01):
        fail("authentication UP flag missing")
    if not (flags & 0x04):
        fail("authentication UV flag missing")

    counter = int.from_bytes(auth_data[33:37], "big")
    old_counter = credential["counter"]
    if old_counter != 0 and counter <= old_counter:
        fail(f"signature counter did not increase: {old_counter} -> {counter}")

    signed_data = auth_data + hashlib.sha256(client_data).digest()
    verify_signature(credential["public_key"], signature, signed_data)

    credential["counter"] = counter
    pending_authenticate = None

    return {
        "ok": True,
        "message": "Authentication verified",
        "credentialId": b64u(raw_id),
        "counter": counter,
        "previousCounter": old_counter,
        "rpIdHash": "PASS",
        "up": "PASS",
        "uv": "PASS",
        "signature": "PASS",
    }


class Handler(SimpleHTTPRequestHandler):
    def _json(self, status, obj):
        payload = json_bytes(obj)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(length))
            path = urlparse(self.path).path
            if path == "/webauthn/register":
                result = verify_registration(body)
            elif path == "/webauthn/authenticate":
                result = verify_authentication(body)
            else:
                self._json(404, {"error": "not found"})
                return
            self._json(200, result)
        except (KeyError, ValueError, base64.binascii.Error) as exc:
            self._json(400, {"error": str(exc)})
        except Exception as exc:
            self._json(500, {"error": f"server error: {exc}"})

    def do_GET(self):
        global pending_register, pending_authenticate
        path = urlparse(self.path).path
        if path == "/webauthn/register-options":
            pending_register = os.urandom(32)
            self._json(200, {"challenge": b64u(pending_register), "rpId": RP_ID,
                             "rpName": "Linux WebAuthn Test"})
            return
        if path == "/webauthn/authenticate-options":
            if not credentials:
                self._json(400, {"error": "register a resident credential first"})
                return
            pending_authenticate = os.urandom(32)
            # Deliberately do not return credentialId. The browser must
            # perform discoverable-credential selection at the authenticator.
            self._json(200, {"challenge": b64u(pending_authenticate), "rpId": RP_ID})
            return
        super().do_GET()

    def log_message(self, fmt, *args):
        print("HTTP:", fmt % args)


if __name__ == "__main__":
    print(f"Linux WebAuthn test server: {ORIGIN}")
    print("Server-side WebAuthn verification enabled")
    print("Resident/discoverable credential authentication enabled")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
