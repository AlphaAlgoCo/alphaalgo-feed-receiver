"""Validation tests for Docker Compose HTTPS/Tunnel profiles and Caddyfile."""
from __future__ import annotations

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class TestDeployConfigs(unittest.TestCase):
    def test_docker_compose_profiles_and_security_defaults(self) -> None:
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

        # Receiver stays bound strictly to loopback on the host.
        self.assertIn('"127.0.0.1:9091:9091"', compose)
        self.assertNotIn('"9091:9091"', compose)
        self.assertNotIn('"0.0.0.0:9091:9091"', compose)

        # Optional profiles must never block default `docker compose up`
        # via parse-time `${VAR:?...}` errors.
        self.assertNotIn(":?", compose)

        # All three HTTPS/tunnel profiles and persistent TLS volumes exist.
        self.assertIn('profiles: ["https"]', compose)
        self.assertIn('profiles: ["tunnel"]', compose)
        self.assertIn('profiles: ["named-tunnel"]', compose)
        self.assertIn("image: caddy:2-alpine", compose)
        self.assertIn("image: cloudflare/cloudflared:latest", compose)
        self.assertIn(
            "./deploy/Caddyfile.docker:/etc/caddy/Caddyfile:ro", compose
        )
        self.assertIn("caddy_data:/data", compose)
        self.assertIn("caddy_config:/config", compose)
        self.assertIn("no-new-privileges:true", compose)
        self.assertIn("condition: service_healthy", compose)

    def test_caddyfile_enforces_hardened_https_reverse_proxy(self) -> None:
        caddyfile = ROOT / "deploy" / "Caddyfile.docker"
        self.assertTrue(caddyfile.is_file())
        text = caddyfile.read_text(encoding="utf-8")
        self.assertIn("{$ALPHAALGO_DOMAIN}", text)
        self.assertIn("reverse_proxy alphaalgo-receiver:9091", text)
        self.assertIn("max_size 64KB", text)
        self.assertIn("-Server", text)
        self.assertIn("Strict-Transport-Security", text)
        self.assertIn("X-Content-Type-Options", text)

    def test_env_example_documents_https_and_tunnel_vars_safely(self) -> None:
        text = (ROOT / ".env.example").read_text(encoding="utf-8")
        self.assertIn("ALPHAALGO_DOMAIN=feed.yourdomain.com", text)
        self.assertIn("CLOUDFLARE_TUNNEL_TOKEN=", text)
        self.assertIn("whsec_REPLACE_WITH_YOUR_SIGNING_SECRET", text)
        self.assertNotIn("TELEGRAM_CHAT_ID=-100", text)


if __name__ == "__main__":
    unittest.main()
