"""Labelled benchmark corpus generator.

Every file holds EITHER one real-looking secret ("positive") or tempting non-secrets
("decoy"). All values are generated at runtime from fixed seeds, are syntactically valid for
their provider but are NOT real credentials, and never touch the network.

IMPORTANT LIMITATION: this corpus is synthetic and authored by the tool's author. It measures
regressions and relative improvements; it is not a substitute for evaluation on real-world
leaks, and absolute numbers must not be compared with other tools' published claims.
"""
from __future__ import annotations

import json
import random
import string
from pathlib import Path

ALNUM = string.ascii_letters + string.digits
B64 = ALNUM + "+/"


def rnd(rng: random.Random, n: int, alphabet: str = ALNUM) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def pem(rng: random.Random, kind: str = "RSA PRIVATE KEY", lines: int = 25) -> str:
    body = "\n".join(rnd(rng, 64, B64) for _ in range(lines))
    return f"-----BEGIN {kind}-----\n{body}\n-----END {kind}-----\n"


def positives(rng: random.Random) -> dict[str, tuple[str, str]]:
    """name -> (file name, content)"""
    h = lambda n: "".join(rng.choice("0123456789abcdef") for _ in range(n))
    out = {
        "aws_pair": ("aws.env", f"AWS_ACCESS_KEY_ID=AKIA{rnd(rng,16,string.ascii_uppercase+string.digits)}\nAWS_SECRET_ACCESS_KEY={rnd(rng,40,B64)}\n"),
        "aws_temp": ("aws_tmp.env", f"KEY=ASIA{rnd(rng,16,string.ascii_uppercase+string.digits)}\n"),
        "github_pat": ("ci.yml", f"token: ghp_{rnd(rng,36)}\n"),
        "github_app": ("app.env", f"GH=ghs_{rnd(rng,36)}\n"),
        "github_fine": ("fine.env", f"GH=github_pat_{rnd(rng,22)}_{rnd(rng,59)}\n"),
        "gitlab": ("gl.env", f"GITLAB_TOKEN=glpat-{rnd(rng,20)}\n"),
        "openai_legacy": ("oa.py", f'client = OpenAI(api_key="sk-{rnd(rng,48)}")\n'),
        "openai_proj": ("oa2.env", f"OPENAI_API_KEY=sk-proj-{rnd(rng,100)}\n"),
        "anthropic": ("an.env", f"ANTHROPIC_API_KEY=sk-ant-api03-{rnd(rng,93)}AA\n"),
        "huggingface": ("hf.env", f"HF_TOKEN=hf_{rnd(rng,34)}\n"),
        "stripe_live": ("pay.py", f'stripe.api_key = "sk_live_{rnd(rng,30)}"\n'),
        "stripe_restricted": ("pay2.env", f"STRIPE=rk_live_{rnd(rng,30)}\n"),
        "slack_bot": ("slack.env", f"SLACK_BOT_TOKEN=xoxb-{rnd(rng,11,string.digits)}-{rnd(rng,11,string.digits)}-{rnd(rng,24)}\n"),
        "slack_user": ("slack2.env", f"SLACK=xoxp-{rnd(rng,12,string.digits)}-{rnd(rng,12,string.digits)}-{rnd(rng,12,string.digits)}-{h(32)}\n"),
        "slack_webhook": ("hook.sh", f"curl -X POST https://hooks.slack.com/services/T{rnd(rng,8,string.ascii_uppercase)}/B{rnd(rng,8,string.ascii_uppercase)}/{rnd(rng,24)}\n"),
        "sendgrid": ("mail.env", f"SENDGRID_API_KEY=SG.{rnd(rng,22,ALNUM+'_-')}.{rnd(rng,43,ALNUM+'_-')}\n"),
        "twilio": ("sms.env", f"TWILIO_ACCOUNT_SID=AC{h(32)}\nTWILIO_AUTH_TOKEN={h(32)}\n"),
        "npm": (".npmrc", f"//registry.npmjs.org/:_authToken=npm_{rnd(rng,36)}\n"),
        "pypi": ("pypirc", f"password = pypi-{rnd(rng,120,ALNUM+'_-')}\n"),
        "digitalocean": ("do.env", f"DO_TOKEN=dop_v1_{h(64)}\n"),
        "google_api": ("maps.js", f"const key = 'AIza{rnd(rng,35,ALNUM+'_-')}';\n"),
        "db_postgres": ("db.yml", f"url: postgres://app:{rnd(rng,16)}@db.prod.acme-corp.net:5432/app\n"),
        "db_redis_nouser": ("cache.env", f"REDIS_URL=redis://:{rnd(rng,20)}@cache.acme-corp.net:6379/0\n"),
        "db_mongo": ("mongo.env", f"MONGO=mongodb+srv://admin:{rnd(rng,16)}@cluster0.abcde.mongodb.net/prod\n"),
        "pem_rsa": ("id_rsa", pem(rng, "RSA PRIVATE KEY")),
        "pem_openssh": ("id_ed25519", pem(rng, "OPENSSH PRIVATE KEY", 6)),
        "pem_encrypted": ("enc.key", pem(rng, "ENCRYPTED PRIVATE KEY", 12)),
        "pem_ec": ("ec.pem", pem(rng, "EC PRIVATE KEY", 5)),
        "gcp_sa": ("sa.json", json.dumps({
            "type": "service_account", "project_id": "acme-prod", "private_key_id": h(40),
            "client_email": "deploy@acme-prod.iam.gserviceaccount.com",
            "private_key": pem(rng, "PRIVATE KEY", 25)}, indent=2)),
        "azure_secret": ("az.env", f"AZURE_CLIENT_SECRET={rnd(rng,3)}8Q~{rnd(rng,34,ALNUM+'_.-')}\n"),
        "generic_password": ("settings.py", f'DB_PASSWORD = "{rnd(rng,14)}!x"\n'),
        "generic_token_hex": ("app.env", f"API_TOKEN={h(32)}\n"),
        "telegram": ("bot.env", f"BOT={rnd(rng,9,string.digits)}:AA{rnd(rng,33,ALNUM+'_-')}\n"),
    }
    return out


def decoys(rng: random.Random) -> dict[str, tuple[str, str]]:
    h = lambda n: "".join(rng.choice("0123456789abcdef") for _ in range(n))
    uid = lambda: f"{h(8)}-{h(4)}-{h(4)}-{h(4)}-{h(12)}"
    return {
        "placeholder_db": ("docs.md", "DATABASE_URL=postgres://user:password@localhost:5432/mydb\n"),
        "angle_db": ("README.txt", "postgres://<user>:<password>@<host>/<db>\n"),
        "env_ref_db": ("compose.yml", "url: postgres://app:${DB_PASSWORD}@db/app\n"),
        "code_ref_password": ("auth.py", "password = get_password()\nsecret_key = os.environ.get('SECRET_KEY')\n"),
        "settings_ref": ("conf.py", "client_secret = settings.azure_ad_client_secret_value_here_xx\n"),
        "node_env_ref": ("conf.ts", "clientSecret = process.env.AZURE_CLIENT_SECRET_FROM_KEYVAULT_VALUE\n"),
        "kebab_slug": ("slug.py", "name = my-disk-encryption-configuration-for-production-servers-in-datacenter\n"),
        "uuids_api_key_line": ("trace.py", f'api_key_request_id = "{uid()}"\n'),
        "git_sha": ("deploy.sh", f"git checkout {h(40)}\n"),
        "sha256_checksum": ("CHECKSUMS.txt", f"{h(64)}  release.tar.gz\n"),
        "lock_integrity": ("package-lock.json", '{"integrity": "sha512-' + rnd(rng, 86, B64) + '=="}\n'),
        "placeholder_token": ("example.env", "API_TOKEN=your_api_token_here\nSECRET=changeme\n"),
        "template_secret": ("tpl.yml", "token: ${{ secrets.DEPLOY_TOKEN }}\n"),
        "csrf_template": ("form.html", "<input name='token' value='{{ csrf_token }}'>\n"),
        "long_identifier": ("big.py", "result = VeryLongFunctionNameInCamelCaseWithoutAnyDigitsAtAll(x)\n"),
        "file_path": ("paths.txt", "/usr/local/lib/python3.12/site-packages/some/very/long/package/path/module.py\n"),
        "pem_header_in_code": ("check.py", 'if "-----BEGIN RSA PRIVATE KEY-----" in text:\n    raise ValueError\n'),
        "type_hint_token": ("sig.py", "def verify(token: str, secret: bytes) -> bool:\n    return True\n"),
        "readme_example_key": ("api.md", "Set `OPENAI_API_KEY=sk-your-key-here` in your shell.\n"),
        "public_stripe_pub": ("pub.js", f"const pk = 'pk_live_{rnd(rng,30)}';\n"),
    }


def build(directory: Path, seed: int = 1905) -> dict:
    """Write the corpus and return labels: {'positives': [...paths], 'decoys': [...paths]}."""
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
