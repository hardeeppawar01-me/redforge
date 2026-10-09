from urllib.parse import urljoin, urlparse

import requests

from config import DEFAULT_CONFIG


class ReconScanner:

    def __init__(self, target, config=None):

        self.config = config or DEFAULT_CONFIG

        self.target = self.normalize_url(target)

        self.session = requests.Session()

        self.session.headers.update({
            "User-Agent": self.config.user_agent
        })

    @staticmethod
    def normalize_url(target):

        target = target.strip()

        if not target.startswith(("http://", "https://")):
            target = "http://" + target

        parsed = urlparse(target)

        if not parsed.netloc:
            raise ValueError("Invalid target URL")

        return target.rstrip("/")

    def fetch(self, url=None):

        url = url or self.target

        try:

            response = self.session.get(
                url,
                timeout=self.config.timeout,
                allow_redirects=self.config.follow_redirects,
                verify=self.config.verify_ssl
            )

            return {
                "success": True,
                "url": response.url,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "content_length": len(response.content),
                "text": response.text
            }

        except requests.RequestException as error:

            return {
                "success": False,
                "url": url,
                "error": str(error)
            }

    def discover_common_paths(self):

        results = []

        for path in self.config.common_paths:

            if len(results) >= self.config.max_endpoints:
                break

            url = urljoin(
                self.target + "/",
                path.lstrip("/")
            )

            result = self.fetch(url)

            result["path"] = path

            results.append(result)

        return results

    def collect(self):

        root_result = self.fetch()

        if not root_result["success"]:

            return {
                "target": self.target,
                "reachable": False,
                "root": root_result,
                "endpoints": []
            }

        return {
            "target": self.target,
            "reachable": True,
            "root": root_result,
            "endpoints": self.discover_common_paths()
        }


def run_recon(target):

    scanner = ReconScanner(target)

    return scanner.collect()
