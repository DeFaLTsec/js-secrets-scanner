"""Descarga páginas, JS y source maps de forma asíncrona."""
from __future__ import annotations

import asyncio
import json
import re
from urllib.parse import urljoin, urlparse

import httpx

SCRIPT_SRC = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.IGNORECASE)
SOURCEMAP = re.compile(r"//[#@]\s*sourceMappingURL=([^\s]+)")
JS_REFS = re.compile(r"[\"']((?:https?:)?/?[\w./\-]+\.js)(?:\?[^\"']*)?[\"']")


class Fetcher:
    def __init__(self, proxy=None, headers=None, concurrency=10, insecure=False, timeout=15):
        self.sem = asyncio.Semaphore(concurrency)
        self.client = httpx.AsyncClient(
            proxy=proxy, headers=headers or {}, verify=not insecure,
            timeout=timeout, follow_redirects=True,
        )

    async def close(self):
        await self.client.aclose()

    async def get(self, url: str) -> str | None:
        async with self.sem:
            try:
                r = await self.client.get(url)
                if r.status_code == 200:
                    return r.text
            except httpx.HTTPError:
                pass
        return None

    async def collect(self, target: str, follow_maps: bool = True) -> dict[str, str]:
        """Devuelve {fuente: contenido} para un objetivo (página o .js)."""
        out: dict[str, str] = {}
        body = await self.get(target)
        if body is None:
            return out
        out[target] = body  # el HTML también puede contener secretos inline
        urls: set[str] = set()
        if not urlparse(target).path.endswith(".js"):
            for src in SCRIPT_SRC.findall(body):
                urls.add(urljoin(target, src))
        # JS referenciados desde otros JS (chunks de webpack, etc.)
        for _ in range(2):
            new = set()
            for u in urls:
                if u in out:
                    continue
                js = await self.get(u)
                if js is None:
                    continue
                out[u] = js
                for ref in JS_REFS.findall(js):
                    if ref.startswith("//"):
                        ref = "https:" + ref
                    new.add(urljoin(u, ref))
            urls = {u for u in new if u not in out}
        if follow_maps:
            for u, js in list(out.items()):
                m = SOURCEMAP.search(js)
                if m and not m.group(1).startswith("data:"):
                    mp = urljoin(u, m.group(1))
                    raw = await self.get(mp)
                    if raw:
                        try:
                            data = json.loads(raw)
                            for name, content in zip(data.get("sources", []), data.get("sourcesContent") or []):
                                if content:
                                    out[f"{mp}::{name}"] = content
                        except json.JSONDecodeError:
                            pass
        return out
