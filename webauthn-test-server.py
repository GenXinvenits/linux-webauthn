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

STATE_FILE = os.path.expanduser("~/.local/state/linux-webauthn-test/credentials.json")
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


def load_credentials():
    global credentials
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as fp:
            stored = json.load(fp)
    except FileNotFoundError:
        credentials = {}
        return
    except Exception as exc:
        print(f"WARNING: unable to load test-server credential state: {exc}")
        credentials = {}
        return

    if not isinstance(stored, dict):
        print("WARNING: invalid test-server credential state; starting empty")
        credentials = {}
        return

    loaded = {}
    for credential_id, credential in stored.items():
        if not isinstance(credential, dict):
            continue
        try:
            loaded[credential_id] = {
                "id": unb64u(credential["id"]),
                "public_key": unb64u(credential["public_key"]),
                "counter": int(credential.get("counter", 0)),
                "flags": int(credential.get("flags", 0)),
            }
        except Exception:
            print(f"WARNING: skipping invalid stored credential {credential_id}")

    credentials = loaded
    print(f"Loaded {len(credentials)} persisted test-server credential(s)")


def save_credentials():
    directory = os.path.dirname(STATE_FILE)
    os.makedirs(directory, mode=0o700, exist_ok=True)

    stored = {
        credential_id: {
            "id": b64u(credential["id"]),
            "public_key": b64u(credential["public_key"]),
            "counter": credential["counter"],
            "flags": credential["flags"],
        }
        for credential_id, credential in credentials.items()
    }

    temporary = STATE_FILE + ".tmp"
    with open(temporary, "w", encoding="utf-8") as fp:
        json.dump(stored, fp, indent=2, sort_keys=True)
        fp.write("\n")
    os.replace(temporary, STATE_FILE)
    os.chmod(STATE_FILE, 0o600)


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

    credential_id = b64u(raw_id)
    credentials[credential_id] = {
        "id": raw_id,
        "public_key": public_key_spki,
        "counter": int.from_bytes(auth_data[33:37], "big"),
        "flags": flags,
    }
    save_credentials()
    pending_register = None

    print(f"Registered credential {credential_id}; total credentials: {len(credentials)}")

    return {
        "ok": True,
        "message": "Registration verified",
        "credentialId": credential_id,
        "counter": credentials[credential_id]["counter"],
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
            ["openssl", "pkey", "-pubin", "-inform", "DER", "-in", key_path, "-out", pem_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        if r.returncode != 0:
            fail("stored public key is invalid")

        r = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", pem_path, "-signature", sig_path, data_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
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

    credential_id = b64u(raw_id)
    credential = credentials.get(credential_id)
    print(f"Authentication selected credential {credential_id}; server knows {len(credentials)} credential(s)")

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
    save_credentials()
    pending_authenticate = None

    return {
        "ok": True,
        "message": "Authentication verified",
        "credentialId": credential_id,
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
            self._json(200, {
                "challenge": b64u(pending_register),
                "rpId": RP_ID,
                "rpName": "Linux WebAuthn Test",
            })
            return

        if path == "/webauthn/authenticate-options":
            if not credentials:
                self._json(400, {"error": "register a resident credential first"})
                return

            pending_authenticate = os.urandom(32)
            self._json(200, {
                "challenge": b64u(pending_authenticate),
                "rpId": RP_ID,
                "storedCredentials": len(credentials),
            })
            return

        super().do_GET()

    def log_message(self, fmt, *args):
        print("HTTP:", fmt % args)


if __name__ == "__main__":
    load_credentials()
    print(f"Linux WebAuthn test server: {ORIGIN}")
    print("Server-side WebAuthn verification enabled")
    print("Resident/discoverable credential authentication enabled")
    print(f"Credential state file: {STATE_FILE}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
