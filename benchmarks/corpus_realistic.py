"""Benchmark corpus "realistic": structurally VALID credentials.

The first corpus (corpus.py) uses random strings that merely look like credentials. Tools that
validate format (key parsing, embedded markers, checksums) reject those by design, which unfairly
penalises them. This corpus fixes that:

* private keys are real, freshly generated RSA / EC / Ed25519 keys (needs `cryptography`)
* GCP service-account JSON embeds a real generated key
* OpenAI keys carry the `T3BlbkFJ` marker; GitHub classic tokens carry their CRC32/base62 checksum
* decoys include real public keys and certificates, UUIDs, hashes, base64 blobs and model names

All values are freshly generated, are not credentials for anything, and never touch the network.
Private keys differ on every run (they cannot be seeded); everything else is deterministic.
"""
from __future__ import annotations

import json
import random
import string
import zlib
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    from cryptography.x509.oid import NameOID
    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    HAVE_CRYPTO = False

ALNUM = string.ascii_letters + string.digits
B64 = ALNUM + "+/"
_B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def rnd(rng: random.Random, n: int, alphabet: str = ALNUM) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def _base62(num: int, width: int = 6) -> str:
    out = ""
    while num:
        num, r = divmod(num, 62)
        out = _B62[r] + out
    return out.rjust(width, "0")


def github_classic_token(rng: random.Random) -> str:
    """ghp_ + 30 random chars + 6-char base62 CRC32 checksum of those 30 chars."""
    body = rnd(rng, 30)
    return "ghp_" + body + _base62(zlib.crc32(body.encode()))


def _pem(key, fmt, encoding=None) -> str:
    return key.private_bytes(
        encoding or serialization.Encoding.PEM, fmt, serialization.NoEncryption()
    ).decode()


def _keys() -> dict[str, str]:
    rsa_key = rsa.generate_private_key(65537, 2048)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ed_key = ed25519.Ed25519PrivateKey.generate()
    return {
        "rsa_pkcs1": _pem(rsa_key, serialization.PrivateFormat.TraditionalOpenSSL),
        "rsa_pkcs8": _pem(rsa_key, serialization.PrivateFormat.PKCS8),
        "ec_pkcs8": _pem(ec_key, serialization.PrivateFormat.PKCS8),
        "ed25519_openssh": _pem(ed_key, serialization.PrivateFormat.OpenSSH),
        "rsa_encrypted": rsa_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"correct horse"),
        ).decode(),
        "_rsa_public": rsa_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode(),
        "_cert": x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.test")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.test")]))
        .public_key(rsa_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(__import__("datetime").datetime(2026, 1, 1))
        .not_valid_after(__import__("datetime").datetime(2027, 1, 1))
        .sign(rsa_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode(),
        "_pkcs8_for_gcp": _pem(rsa_key, serialization.PrivateFormat.PKCS8),
    }


def positives(rng: random.Random) -> dict[str, tuple[str, str]]:
    h = lambda n: "".join(rng.choice("0123456789abcdef") for _ in range(n))
    up = string.ascii_uppercase + string.digits
    out = {
        "aws_pair": ("aws.env", f"AWS_ACCESS_KEY_ID=AKIA{rnd(rng,16,up)}\nAWS_SECRET_ACCESS_KEY={rnd(rng,40,B64)}\n"),
        "github_classic": ("ci.yml", f"token: {github_classic_token(rng)}\n"),
        "github_fine": ("fine.env", f"GH=github_pat_{rnd(rng,22)}_{rnd(rng,59)}\n"),
        "gitlab": ("gl.env", f"GITLAB_TOKEN=glpat-{rnd(rng,20,ALNUM+'_-')}\n"),
        "openai_legacy": ("oa.py", f'client = OpenAI(api_key="sk-{rnd(rng,20)}T3BlbkFJ{rnd(rng,20)}")\n'),
        "openai_proj": ("oa2.env", f"OPENAI_API_KEY=sk-proj-{rnd(rng,58,ALNUM+'_-')}T3BlbkFJ{rnd(rng,58,ALNUM+'_-')}\n"),
        "anthropic": ("an.env", f"ANTHROPIC_API_KEY=sk-ant-api03-{rnd(rng,93,ALNUM+'_-')}AA\n"),
        "huggingface": ("hf.env", f"HF_TOKEN=hf_{rnd(rng,34)}\n"),
        "stripe_live": ("pay.py", f'stripe.api_key = "sk_live_{rnd(rng,99)}"\n'),
        "stripe_restricted": ("pay2.env", f"STRIPE=rk_live_{rnd(rng,99)}\n"),
        "slack_bot": ("slack.env", f"SLACK_BOT_TOKEN=xoxb-{rnd(rng,12,string.digits)}-{rnd(rng,13,string.digits)}-{rnd(rng,24)}\n"),
        "slack_webhook": ("hook.sh", f"curl -X POST https://hooks.slack.com/services/T{rnd(rng,10,string.ascii_uppercase+string.digits)}/B{rnd(rng,10,string.ascii_uppercase+string.digits)}/{rnd(rng,24)}\n"),
        "sendgrid": ("mail.env", f"SENDGRID_API_KEY=SG.{rnd(rng,22,ALNUM+'_-')}.{rnd(rng,43,ALNUM+'_-')}\n"),
        "twilio": ("sms.env", f"TWILIO_ACCOUNT_SID=AC{h(32)}\nTWILIO_AUTH_TOKEN={h(32)}\n"),
        "npm": (".npmrc", f"//registry.npmjs.org/:_authToken=npm_{rnd(rng,36)}\n"),
        "pypi": ("pypirc", f"password = pypi-AgEIcHlwaS5vcmc{rnd(rng,150,ALNUM+'_-')}\n"),
        "digitalocean": ("do.env", f"DO_TOKEN=dop_v1_{h(64)}\n"),
        "google_api": ("maps.js", f"const key = 'AIza{rnd(rng,35,ALNUM+'_-')}';\n"),
        "db_postgres": ("db.yml", f"url: postgres://app:{rnd(rng,16)}@db.prod.acme-corp.net:5432/app\n"),
        "db_mongo": ("mongo.env", f"MONGO=mongodb+srv://admin:{rnd(rng,16)}@cluster0.abcde.mongodb.net/prod\n"),
        "azure_secret": ("az.env", f"AZURE_CLIENT_SECRET={rnd(rng,3)}8Q~{rnd(rng,34,ALNUM+'_.-')}\n"),
        "generic_password": ("settings.py", f'DB_PASSWORD = "{rnd(rng,14)}!x"\n'),
    }
    if HAVE_CRYPTO:
        keys = _keys()
        for name in ("rsa_pkcs1", "rsa_pkcs8", "ec_pkcs8", "ed25519_openssh", "rsa_encrypted"):
            out[f"pem_{name}"] = (f"{name}.pem", keys[name])
        out["gcp_service_account"] = ("sa.json", json.dumps({
            "type": "service_account", "project_id": "acme-prod", "private_key_id": h(40),
            "client_email": "deploy@acme-prod.iam.gserviceaccount.com",
            "private_key": keys["_pkcs8_for_gcp"]}, indent=2))
    return out


def decoys(rng: random.Random) -> dict[str, tuple[str, str]]:
    h = lambda n: "".join(rng.choice("0123456789abcdef") for _ in range(n))
    uid = lambda: f"{h(8)}-{h(4)}-{h(4)}-{h(4)}-{h(12)}"
    out = {
        "placeholder_db": ("docs.md", "DATABASE_URL=postgres://user:password@localhost:5432/mydb\n"),
        "env_ref_db": ("compose.yml", "url: postgres://app:${DB_PASSWORD}@db/app\n"),
        "code_ref_password": ("auth.py", "password = get_password()\nsecret_key = os.environ.get('SECRET_KEY')\n"),
        "node_env_ref": ("conf.ts", "const token = process.env.GITHUB_TOKEN;\n"),
        "uuid_in_config": ("trace.yml", f"request_id: {uid()}\ntrace_id: {uid()}\n"),
        "git_sha": ("deploy.sh", f"git checkout {h(40)}\n"),
        "sha256_checksum": ("CHECKSUMS.txt", f"{h(64)}  release.tar.gz\n"),
        "lock_integrity": ("deps.json", '{"integrity": "sha512-' + rnd(rng, 86, B64) + '=="}\n'),
        "base64_image": ("logo.css", "a{background:url(data:image/png;base64," + rnd(rng, 400, B64) + ")}\n"),
        "model_names": ("models.py", 'MODELS = ["gpt-4-turbo-preview", "claude-3-opus-20240229", "text-embedding-3-small"]\n'),
        "template_secret": ("tpl.yml", "token: ${{ secrets.DEPLOY_TOKEN }}\n"),
        "placeholder_token": ("example.env", "API_TOKEN=your_api_token_here\nSECRET=changeme\n"),
        "readme_example_key": ("api.md", "Set `OPENAI_API_KEY=sk-your-key-here` in your shell.\n"),
        "aws_docs_style": ("docs.md", "export AWS_ACCESS_KEY_ID=<your-access-key-id>\nexport AWS_SECRET_ACCESS_KEY=<your-secret>\n"),
        "long_identifier": ("big.py", "result = VeryLongFunctionNameInCamelCaseWithoutAnyDigitsAtAll(x)\n"),
        "url_with_hash": ("links.md", f"https://example.com/releases/download/v1.2.3/app-{h(32)}.zip\n"),
        "css_colors": ("style.css", "color:#a1b2c3;background:#00ff7f;border:1px solid #1e90ff;\n"),
        "stripe_publishable": ("pub.js", f"const pk = 'pk_live_{rnd(rng,99)}';\n"),
    }
    if HAVE_CRYPTO:
        keys = _keys()
        out["public_key"] = ("id_rsa.pub.pem", keys["_rsa_public"])
        out["certificate"] = ("server.crt", keys["_cert"])
    return out


def build(directory: Path, seed: int = 1905) -> dict:
    rng = random.Random(seed)
    directory.mkdir(parents=True, exist_ok=True)
    labels = {"positives": [], "decoys": []}
    for kind, items in (("positives", positives(rng)), ("decoys", decoys(rng))):
        for name, (fname, content) in items.items():
            rel = Path(kind) / name / fname
            path = directory / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            labels[kind].append(rel.as_posix())
    (directory / "labels.json").write_text(json.dumps(labels, indent=2))
    return labels
