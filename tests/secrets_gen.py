"""Planted fake secrets, assembled at runtime so no secret-looking literal exists in the repo."""
from __future__ import annotations

from dataclasses import dataclass

B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return total % 10 == 0


def luhn_complete(prefix14: str) -> str:
    for check in "0123456789":
        if luhn_ok(prefix14 + check):
            return prefix14 + check
    raise AssertionError("unreachable")


def not_luhn(prefix14: str) -> str:
    for check in "0123456789":
        if not luhn_ok(prefix14 + check):
            return prefix14 + check
    raise AssertionError("unreachable")


def b64_key(seed: int = 7) -> str:
    return "".join(B64[(seed * (i + 3) + i * i) % 64] for i in range(43)) + "="


@dataclass(frozen=True)
class Sample:
    name: str
    redact_rule: str
    gitleaks_rules: tuple[str, ...]
    text: str
    values: tuple[str, ...]
    disable: tuple[str, ...]  # redact rules that must be off for the secret to survive

    @property
    def path(self) -> str:
        return f"etc/{self.name}.txt"


def build_samples() -> tuple[Sample, ...]:
    wg = b64_key(7)
    wg2 = b64_key(11)
    imei = luhn_complete("86123456789012")
    imsi = not_luhn("31015012345678")
    iccid = "89" + "01260123456789012" + "3"
    sk = "sk-" + "ant-" + "api03-" + "Zx9" * 10
    bearer = "Qw3rTy" * 5
    crypt = "$" + "6" + "$" + "saltsalt" + "$" + "H4shH4shH4shH4sh" * 2
    pem_body = "\n".join(["MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC" + "x" * 13] * 3)
    pem = "-----BEGIN " + "PRIVATE KEY-----\n" + pem_body + "\n-----END " + "PRIVATE KEY-----"
    jsid = "9f86d081884c7d659a2feaa0c55ad015"
    bare_imsi = not_luhn("26201123456789")
    pgp = "-----BEGIN " + "PGP PRIVATE KEY BLOCK-----\n" + "\n".join(["lQdGBF" + "x" * 58] * 3) + "\n"
    return (
        Sample("json", "json-secret", ("json-secret-value",),
               '{"result": 1, "password": "Zp4secretValue"}\n', ("Zp4secretValue",), ("json-secret",)),
        Sample("jsonsid", "json-secret", ("json-rpc-sid",),
               '{"method":"call","params":["' + jsid + '","modem","get_info",{}]}\n', (jsid,), ("json-secret",)),
        Sample("ucishell", "uci-sensitive", ("uci-set-secret",),
               "uci set wireless.default_radio0.key='Tr0ub4dorXYZ'\n", ("Tr0ub4dorXYZ",), ("uci-sensitive", "token", "labelled-secret")),
        Sample("pgp", "pem-block", ("private-key-begin",), "keyring\n" + pgp, ("lQdGBF" + "x" * 58,), ("pem-block",)),
        Sample("imsibare", "imsi", ("imei-like-digit-run",), f"registered on {bare_imsi} ok\n", (bare_imsi,), ("imsi",)),
        Sample("passvar", "wifi-psk", ("assign-secret-name",), "export ap_password=Pl4inTextPw\n",
               ("Pl4inTextPw",), ("wifi-psk", "labelled-secret")),
        Sample("uci", "uci-sensitive", ("uci-secret-option",),
               "config wifi-iface\n\toption passwd 'Zq8xLm2vTn'\n", ("Zq8xLm2vTn",), ("uci-sensitive",)),
        Sample("wifi", "wifi-psk", ("wifi-psk-line",),
               "country=CA\nwpa_passphrase=correct-horse-battery-staple\n",
               ("correct-horse-battery-staple",), ("wifi-psk", "labelled-secret")),
        Sample("wgblob", "wg-key", ("wg-base64-44",), f"# peer blob {wg2}\n", (wg2,), ("wg-key",)),
        Sample("wgline", "wg-key", ("wg-key-line", "wg-base64-44"),
               f"[Interface]\nPrivateKey = {wg}\n", (wg,), ("wg-key", "token", "labelled-secret")),
        Sample("wgopt", "wg-key", ("wg-key-option", "uci-secret-option", "wg-base64-44"),
               f"config wireguard_wg0\n\toption private_key '{wg2}'\n", (wg2,), ("wg-key", "uci-sensitive", "token")),
        Sample("pem", "pem-block", ("private-key-pem",), f"cert follows\n{pem}\nend\n", (pem_body.splitlines()[0],), ("pem-block",)),
        Sample("hash", "pw-hash", ("crypt-hash",), f"root:{crypt}:19000:0:99999:7:::\n", (crypt,), ("pw-hash",)),
        Sample("imei", "imei", ("imei-like-digit-run",), f"modem id {imei} seen\n", (imei,), ("imei",)),
        Sample("imsi", "imsi", ("imei-like-digit-run",), f"IMSI: {imsi}\n", (imsi,), ("imsi",)),
        Sample("iccid", "iccid", ("iccid",), f"sim card {iccid} inserted\n", (iccid,), ("iccid",)),
        Sample("bearer", "token", ("bearer-token",), f"Authorization: Bearer {bearer}\n", (bearer,), ("token", "auth-header")),
        Sample("skkey", "token", ("api-key-sk",), f"curl -H 'x-note: {sk}'\n", (sk,), ("token",)),
    )


MAC = "dc:a6:32:11:22:33"
