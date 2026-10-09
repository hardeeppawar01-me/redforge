from dataclasses import dataclass, field


@dataclass
class ScannerConfig:
    timeout: int = 10

    user_agent: str = (
        "RedForge/1.0 "
        "(Authorized Security Assessment)"
    )

    max_endpoints: int = 100

    follow_redirects: bool = True

    verify_ssl: bool = False

    common_paths: list = field(default_factory=lambda: [
        "/",
        "/robots.txt",
        "/sitemap.xml",
        "/login",
        "/admin",
        "/api",
        "/api/v1",
        "/api/v2",
        "/swagger",
        "/swagger.json",
        "/openapi.json",
    ])

    security_headers: list = field(default_factory=lambda: [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ])


DEFAULT_CONFIG = ScannerConfig()
