"""
SpecterOSINT - Motor de navegación sigiloso profesional (patchright + Chromium).

Sustituye al motor de navegación embebido en Electron: aquel vivía en el proceso
main de la app y cualquier corrupción en el subsistema de navegador (0xC0000005)
se llevaba la aplicación entera. Ahora corre dentro del engine Python, en
procesos separados de la UI: si un sitio hostil tumba el navegador, el engine
sigue sirviendo /health y la UI sigue viva; el colector cae a su fallback HTTP.

=== Capa anti-detección profesional ===

1. DRIVER: patchright (fork de Playwright con el driver parcheado). Elimina las
   fugas de CDP que delatan a Playwright/Selenium ante fingerprinting avanzado:
   `Runtime.enable` (fuga de consola), `Page.addScriptToEvaluateOnNewDocument`
   detectable, isolated worlds visibles. `navigator.webdriver` es False a nivel
   NATIVO, sin JS que parchear. Webcams de detección: bot.sannysoft, creepjs,
   fingerprintjs pasan mucho más limpio que con Playwright stock.

2. HUELLAS COHERENTES (3 perfiles completos): no basta el UA. Cada perfil lleva
   la terna coherente UA ↔ platform ↔ Sec-CH-UA (client hints) ↔ locale ↔
   timezone ↔ viewport. Un Chrome/131 con `platform: Win32` y client hints de
   Chrome/124 es un bot delatado en el primer request.

3. CABECERAS: `extra_http_headers` del contexto fija Accept-Language coherente
   con el locale y `sec-ch-ua*` de la versión declarada. Chromium las envía en
   cada request; las de fetch/XHR heredan del contexto, sin mezclas.

4. JS (init script, sólo lo que patchright no cubre):
   - navigator.hardwareConcurrency / deviceMemory con valores plausibles (8/8).
   - WebGL vendor/renderer reales (Intel UHD) en vez de "SwiftShader"/"Google
     SwiftShader" — la fuga #1 de Chromium headless.
   - permissions.query de 'notifications' → 'prompt' (fuga clásica headless).
   - chrome.csi/loadTimes presentes (headless no los define).
   - iframe contentWindow.chrome propagado.

5. COMPORTAMIENTO: pausas no deterministas, escritura con delay por tecla,
   viewport a resolución física real y `device_scale_factor=1`.

Lo que NO se hace: no se toca `window.chrome.runtime` con objetos vacíos
botados (creepjs lo caza), no se falsifican APIs que el driver ya cubre, y no
se añaden `--disable-blink-features` más allá de AutomationControlled (más
flags = más huella, no menos).

Uso:
    from specter.stealth_browser import get_browser
    browser = await get_browser()
    results = await browser.search("consulta", engine="bing", top_k=8)
    snap = await browser.navigate_and_snapshot("https://ejemplo.com")
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
import re
import time
from typing import Any
from urllib.parse import quote_plus, urlsplit

try:
    # Driver anti-detección: mismo API que playwright.async_api, driver parcheado.
    from patchright.async_api import async_playwright
except ImportError:  # pragma: no cover - playwright instalado sin patchright
    from playwright.async_api import async_playwright

from specter.netguard import assert_public_http_url

logger = logging.getLogger("specter.stealth_browser")

SEARCH_TIMEOUT_MS = 25_000
NAVIGATE_TIMEOUT_MS = 30_000
SETTLE_DELAY_S = 1.2
SNAPSHOT_MAX_CHARS = 25_000
SNAPSHOT_MAX_LINKS = 100
BROWSER_RESTARTS_WINDOW_S = 60.0
BROWSER_MAX_RESTARTS = 3

# ---------------------------------------------------------------------------
# Huellas de navegador COMPLETAS y coherentes.
# Regla de oro: UA, Sec-CH-UA (client hints), platform, locale, timezone y
# viewport cuentan la misma historia. Mezclar versiones = bot delatado.
# ---------------------------------------------------------------------------
FINGERPRINTS: list[dict[str, Any]] = [
    {
        "label": "win-es",
        "ua": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        ),
        "sec_ch_ua": '"Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131"',
        "sec_ch_ua_platform": '"Windows"',
        "platform": "Win32",
        "locale": "es-ES",
        "languages": ("es-ES", "es", "en"),
        "accept_language": "es-ES,es;q=0.9,en;q=0.8",
        "tz": "Europe/Madrid",
        "viewport": {"width": 1920, "height": 1080},
        "hardware": {"cores": 12, "memory_gb": 16},
        "webgl": {
            "vendor": "Intel Inc.",
            "renderer": "Intel(R) UHD Graphics 630",
        },
    },
    {
        "label": "win-mx",
        "ua": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
        ),
        "sec_ch_ua": '"Chromium";v="130", "Not_A Brand";v="24", "Google Chrome";v="130"',
        "sec_ch_ua_platform": '"Windows"',
        "platform": "Win32",
        "locale": "es-MX",
        "languages": ("es-MX", "es", "en"),
        "accept_language": "es-MX,es;q=0.9,en;q=0.7",
        "tz": "America/Mexico_City",
        "viewport": {"width": 1536, "height": 864},
        "hardware": {"cores": 8, "memory_gb": 8},
        "webgl": {
            "vendor": "Google Inc. (NVIDIA)",
            "renderer": "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
        },
    },
    {
        "label": "mac-ar",
        "ua": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
        ),
        "sec_ch_ua": '"Chromium";v="130", "Not_A Brand";v="24", "Google Chrome";v="130"',
        "sec_ch_ua_platform": '"macOS"',
        "platform": "MacIntel",
        "locale": "es-AR",
        "languages": ("es-AR", "es", "en"),
        "accept_language": "es-AR,es;q=0.9,en;q=0.7",
        "tz": "America/Argentina/Buenos_Aires",
        "viewport": {"width": 1728, "height": 1117},
        "hardware": {"cores": 10, "memory_gb": 16},
        "webgl": {
            "vendor": "Apple Inc.",
            "renderer": "Apple M2",
        },
    },
]

USER_AGENT = FINGERPRINTS[0]["ua"]


async def _guard_browser_request(route: Any) -> None:
    """Block non-public HTTP requests, including redirects and WebSocket handshakes."""
    url = route.request.url
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        logger.warning("stealth-browser: URL malformada bloqueada: %s", exc)
        await route.abort("blockedbyclient")
        return
    scheme = parsed.scheme.lower()
    if scheme in ("data", "blob", "about"):
        await route.continue_()
        return
    if scheme in ("ws", "wss"):
        parsed = parsed._replace(scheme="https" if scheme == "wss" else "http")
        url = parsed.geturl()
    elif scheme not in ("http", "https"):
        await route.abort("blockedbyclient")
        return
    try:
        await asyncio.to_thread(assert_public_http_url, url)
    except ValueError as exc:
        logger.warning("stealth-browser: solicitud bloqueada por NetGuard: %s", exc)
        await route.abort("blockedbyclient")
        return
    await route.continue_()


async def _guard_browser_websocket(route: Any) -> None:
    """Apply NetGuard to WebSocket destinations reached by page scripts."""
    try:
        parsed = urlsplit(route.url)
    except ValueError as exc:
        logger.warning("stealth-browser: URL WebSocket malformada bloqueada: %s", exc)
        await route.close(code=1008, reason="URL bloqueada por NetGuard")
        return
    if parsed.scheme.lower() not in ("ws", "wss"):
        await route.close(code=1008, reason="URL bloqueada por NetGuard")
        return
    public_url = parsed._replace(scheme="https" if parsed.scheme.lower() == "wss" else "http")
    try:
        await asyncio.to_thread(assert_public_http_url, public_url.geturl())
    except ValueError as exc:
        logger.warning("stealth-browser: WebSocket bloqueado por NetGuard: %s", exc)
        await route.close(code=1008, reason="URL bloqueada por NetGuard")
        return
    await route.connect()


def _stealth_init_script(fp: dict[str, Any]) -> str:
    """JS de endurecimiento: SÓLO lo que patchright no cubre nativamente.

    Valores derivados de la huella activa (nada hardcodeado que contradiga al
    resto del perfil). Se ejecuta en cada documento antes que los scripts.
    """
    cores = fp["hardware"]["cores"]
    mem = fp["hardware"]["memory_gb"]
    wgl_vendor = fp["webgl"]["vendor"].replace("'", "\\'")
    wgl_renderer = fp["webgl"]["renderer"].replace("'", "\\'")
    langs = ", ".join(f"'{lang}'" for lang in fp["languages"])
    return f"""
(() => {{
  // hardware plausible y coherente con la huella
  try {{ Object.defineProperty(navigator, 'hardwareConcurrency', {{ get: () => {cores} }}); }} catch (_) {{}}
  try {{ Object.defineProperty(navigator, 'deviceMemory', {{ get: () => {mem} }}); }} catch (_) {{}}
  try {{ Object.defineProperty(navigator, 'languages', {{ get: () => [{langs}] }}); }} catch (_) {{}}

  // plugins: Chrome real expone 5 (PDF viewer incluido); headless llega con 0 y
  // sannysoft lo marca. El objeto fake HEREDA de PluginArray.prototype para que
  // `navigator.plugins instanceof PluginArray` siga siendo true.
  try {{
    if (navigator.plugins.length === 0) {{
      const mkPlugin = (name) => Object.create(Plugin.prototype, {{
        name: {{ value: name }},
        filename: {{ value: 'internal-pdf-viewer' }},
        description: {{ value: 'Portable Document Format' }},
        length: {{ value: 2 }},
      }});
      const fakePlugins = [
        mkPlugin('PDF Viewer'),
        mkPlugin('Chrome PDF Viewer'),
        mkPlugin('Chromium PDF Viewer'),
        mkPlugin('Microsoft Edge PDF Viewer'),
        mkPlugin('WebKit built-in PDF'),
      ];
      const fakePluginArray = Object.create(PluginArray.prototype);
      for (let i = 0; i < fakePlugins.length; i++) {{
        Object.defineProperty(fakePluginArray, i, {{ value: fakePlugins[i], enumerable: true }});
        Object.defineProperty(fakePluginArray, fakePlugins[i].name, {{ value: fakePlugins[i] }});
      }}
      Object.defineProperty(fakePluginArray, 'length', {{ value: fakePlugins.length }});
      fakePluginArray.item = (i) => fakePlugins[i] || null;
      fakePluginArray.namedItem = (n) => fakePlugins.find(p => p.name === n) || null;
      fakePluginArray.refresh = () => {{}};
      Object.defineProperty(navigator, 'plugins', {{ get: () => fakePluginArray }});

      const mkMime = () => Object.create(MimeType.prototype, {{
        type: {{ value: 'application/pdf' }},
        suffixes: {{ value: 'pdf' }},
        description: {{ value: 'Portable Document Format' }},
      }});
      const fakeMimes = [mkMime(), mkMime(), mkMime(), mkMime(), mkMime()];
      const fakeMimeArray = Object.create(MimeTypeArray.prototype);
      for (let i = 0; i < fakeMimes.length; i++) {{
        Object.defineProperty(fakeMimeArray, i, {{ value: fakeMimes[i], enumerable: true }});
      }}
      Object.defineProperty(fakeMimeArray, 'length', {{ value: fakeMimes.length }});
      fakeMimeArray.item = (i) => fakeMimes[i] || null;
      fakeMimeArray.namedItem = (t) => fakeMimes.find(m => m.type === t) || null;
      Object.defineProperty(navigator, 'mimeTypes', {{ get: () => fakeMimeArray }});
      // Enlazar cada plugin a sus mimeTypes (como hace Chrome real).
      for (const plugin of fakePlugins) {{
        Object.defineProperty(plugin, '0', {{ value: fakeMimes[0] }});
        Object.defineProperty(plugin, '1', {{ value: fakeMimes[1] }});
      }}
    }}
  }} catch (_) {{}}

  // WebGL: los UNPAGED headless reportan SwiftShader; los sitios lo leen vía
  // WEBGL_debug_renderer_info. Devolvemos la GPU de la huella activa.
  try {{
    const getParameter = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function (param) {{
      if (param === 37445) return '{wgl_vendor}';      // UNMASKED_VENDOR_WEBGL
      if (param === 37446) return '{wgl_renderer}';    // UNMASKED_RENDERER_WEBGL
      return getParameter.call(this, param);
    }};
    if (window.WebGL2RenderingContext) {{
      const getParameter2 = WebGL2RenderingContext.prototype.getParameter;
      WebGL2RenderingContext.prototype.getParameter = function (param) {{
        if (param === 37445) return '{wgl_vendor}';
        if (param === 37446) return '{wgl_renderer}';
        return getParameter2.call(this, param);
      }};
    }}
  }} catch (_) {{}}

  // permissions.query: headless responde 'denied' a notifications sin haberlo
  // pedido el usuario — fuga documentada por creepjs.
  try {{
    if (window.Notification) {{
      const originalQuery = window.navigator.permissions.query;
      window.navigator.permissions.query = (parameters) => (
        parameters && parameters.name === 'notifications'
          ? Promise.resolve({{ state: Notification.permission }})
          : originalQuery(parameters)
      );
    }}
  }} catch (_) {{}}

  // window.chrome completo (creepjs comprueba la FORMA del objeto, no sólo
  // su existencia): runtime con connect/onconnect, csi y loadTimes funcionales.
  try {{
    window.chrome = window.chrome || {{}};
    window.chrome.runtime = window.chrome.runtime || {{
      connect: () => {{}},
      onConnect: {{ addListener: () => {{}}, removeListener: () => {{}} }},
      onMessage: {{ addListener: () => {{}}, removeListener: () => {{}} }},
      sendMessage: () => {{}},
    }};
    window.chrome.csi = window.chrome.csi || (() => ({{ startE: Date.now(), onloadT: Date.now() }}));
    window.chrome.loadTimes = window.chrome.loadTimes || (() => ({{
      requestTime: Date.now() / 1000,
      startLoadTime: Date.now() / 1000,
      commitLoadTime: Date.now() / 1000,
      finishDocumentLoadTime: Date.now() / 1000,
      finishLoadTime: Date.now() / 1000,
      firstPaintTime: Date.now() / 1000,
      firstPaintAfterLoadTime: 0,
      navigationType: 'Other',
      wasFetchedViaSpdy: false,
      wasNpnNegotiated: true,
      npnNegotiatedProtocol: 'h2',
      wasAlternateProtocolAvailable: false,
      connectionInfo: 'h2',
    }}));
  }} catch (_) {{}}
}})();
"""


# Parseo de resultados EN LA PÁGINA (devuelve JSON serializable). El mismo
# contrato que devolvía el puente /browser/search de Electron.
# Bing envuelve cada resultado en un redirect /ck/a: la URL real está en <cite>.
_GOOGLE_PARSE = """
() => {
  const items = Array.from(document.querySelectorAll('div.g, div[data-sokoban-container]'));
  return items.map(div => {
    const a = div.querySelector('a[href]');
    const h3 = div.querySelector('h3');
    const snip = div.querySelector('.VwiC3b, div[style*="-webkit-line-clamp"]');
    return {
      title: (h3 ? h3.innerText || h3.textContent : '').trim(),
      url: a ? a.href : '',
      snippet: (snip ? snip.innerText || snip.textContent : '').trim(),
    };
  }).filter(r => r.title.length > 0 && r.url.startsWith('http')
      && !r.url.includes('google.com/search'));
}
"""

_BING_PARSE = """
() => {
  const items = Array.from(document.querySelectorAll('li.b_algo'));
  return items.map(li => {
    const a = li.querySelector('h2 a');
    const p = li.querySelector('.b_caption p, .b_algoSlug, p');
    const cite = li.querySelector('cite');
    let url = a ? a.href : '';
    if (url.includes('bing.com/ck/') && cite) {
      const real = (cite.innerText || '').trim().split(' ')[0];
      if (real.startsWith('http')) url = real;
      else if (real) url = 'https://' + real.replace(/^https?:\\/\\//, '');
    }
    return {
      title: (a ? a.innerText || a.textContent : '').trim(),
      url,
      snippet: (p ? p.innerText || p.textContent : '').trim(),
    };
  }).filter(r => r.title.length > 0 && r.url.startsWith('http') && !r.url.includes('bing.com/ck/'));
}
"""

# DuckDuckGo HTML (chromium real): anchor .result__a con redirect uddg=.
_DDG_PARSE = """
() => {
  const out = [];
  for (const a of document.querySelectorAll('a.result__a')) {
    const href = a.href || '';
    let url = href;
    if (href.includes('uddg=')) {
      try {
        url = decodeURIComponent(href.split('uddg=')[1].split('&')[0]);
      } catch (_) { url = href; }
    }
    const snipEl = a.closest('div')?.querySelector('.result__snippet');
    out.push({
      title: (a.innerText || a.textContent || '').trim(),
      url,
      snippet: (snipEl ? snipEl.innerText || snipEl.textContent : '').trim(),
    });
  }
  return out.filter(r => r.title.length > 0 && r.url.startsWith('http'));
}
"""

# Snapshot: título + texto limpio + links (contrato de /browser/snapshot).
_SNAPSHOT_SCRIPT = """
() => {
  const links = Array.from(document.querySelectorAll('a[href]'))
    .map((a, i) => ({
      uid: 'elem-' + i,
      text: (a.innerText || a.textContent || '').trim(),
      href: a.href,
    }))
    .filter(l => l.text.length > 0 && l.href.startsWith('http'))
    .slice(0, 100);

  const clone = document.body ? document.body.cloneNode(true) : null;
  if (!clone) return { title: document.title || '', url: window.location.href, text: '', links };
  const toRemove = clone.querySelectorAll('script, style, noscript, svg, iframe');
  toRemove.forEach(el => el.remove());
  const cleanText = (clone.innerText || clone.textContent || '').replace(/\\s+/g, ' ').trim();
  return {
    title: document.title || '',
    url: window.location.href,
    text: cleanText,
    links,
  };
}
"""


class StealthBrowser:
    """Navegador Chromium sigiloso compartido (singleton asíncrono por proceso)."""

    def __init__(self) -> None:
        self._pw: Any = None
        self._browser: Any = None
        self._context: Any = None
        self._lock = asyncio.Lock()
        self._restart_times: list[float] = []
        self._fp_index = 0
        self._fingerprint: dict[str, Any] = FINGERPRINTS[0]

    # ------------------------------------------------------- propiedades API
    @property
    def fingerprint(self) -> dict[str, Any]:
        """Huella activa (dict, sólo lectura conceptual)."""
        return self._fingerprint

    @property
    def fingerprint_index(self) -> int:
        return self._fp_index % max(1, len(FINGERPRINTS))

    @property
    def restart_times(self) -> list[float]:
        return list(self._restart_times)

    @property
    def is_ready(self) -> bool:
        return self._context is not None

    # ------------------------------------------------------------------ ciclo
    async def _ensure(self) -> None:
        if self._context is not None:
            return
        async with self._lock:
            if self._context is not None:
                return
            fp = FINGERPRINTS[self._fp_index % len(FINGERPRINTS)]
            self._fingerprint = fp
            logger.info(
                "stealth-browser: arrancando Chromium (huella %s, locale %s)…",
                fp["label"],
                fp["locale"],
            )
            self._pw = await async_playwright().start()
            self._browser = await self._pw.chromium.launch(
                headless=True,
                args=[
                    # El único flag "anti-detección" con valor real y bajo coste
                    # de huella; el driver (patchright) hace el resto.
                    "--disable-blink-features=AutomationControlled",
                    "--disable-dev-shm-usage",
                    "--no-first-run",
                    "--no-default-browser-check",
                    # GL real para que WebGL no caiga a SwiftShader en Linux.
                    "--use-gl=angle",
                    "--use-angle=default",
                ],
            )
            # Cabeceras COHERENTES con la huella en TODA petición HTTP del
            # contexto (documento, XHR, fetch). Sec-CH-UA declara la misma
            # versión que el UA: un mismatch aquí es la delación más común.
            self._context = await self._browser.new_context(
                user_agent=fp["ua"],
                locale=fp["locale"],
                timezone_id=fp["tz"],
                viewport=fp["viewport"],
                device_scale_factor=1,
                service_workers="block",
                extra_http_headers={
                    "Accept-Language": fp["accept_language"],
                    "sec-ch-ua": fp["sec_ch_ua"],
                    "sec-ch-ua-mobile": "?0",
                    "sec-ch-ua-platform": fp["sec_ch_ua_platform"],
                },
                storage_state=None,
            )
            await self._context.add_init_script(_stealth_init_script(fp))
            await self._context.route("**/*", _guard_browser_request)
            await self._context.route_web_socket("**/*", _guard_browser_websocket)
            logger.info("stealth-browser: Chromium listo (huella %s)", fp["label"])

    async def _shutdown_locked(self) -> None:
        """Cierra navegador y driver. Debe llamarse con el lock tomado."""
        for attr in ("_context", "_browser"):
            obj = getattr(self, attr, None)
            if obj is not None:
                with contextlib.suppress(Exception):
                    await obj.close()
                setattr(self, attr, None)
        if self._pw is not None:
            with contextlib.suppress(Exception):
                await self._pw.stop()
            self._pw = None

    async def stop(self) -> None:
        async with self._lock:
            await self._shutdown_locked()

    async def _restart(self) -> None:
        """Recrea el navegador (caída del proceso Chromium, context muerto…)."""
        now = time.monotonic()
        self._restart_times = [
            t for t in self._restart_times if now - t < BROWSER_RESTARTS_WINDOW_S
        ]
        if len(self._restart_times) >= BROWSER_MAX_RESTARTS:
            raise RuntimeError(
                f"stealth-browser: {len(self._restart_times)} caídas en "
                f"{BROWSER_RESTARTS_WINDOW_S:.0f}s; se desiste (fallback HTTP del colector)"
            )
        self._restart_times.append(now)
        logger.warning(
            "stealth-browser: reiniciando navegador (intento %d)…", len(self._restart_times)
        )
        await self._shutdown_locked()
        await self._ensure()

    def rotate_fingerprint(self) -> dict[str, Any]:
        """Rota la huella para la PRÓXIMA sesión (combinar con recycle_context)."""
        self._fp_index += 1
        self._fingerprint = FINGERPRINTS[self._fp_index % len(FINGERPRINTS)]
        return self._fingerprint

    async def recycle_context(self) -> None:
        """Cierra contexto y navegador aplicando la huella rotada en el próximo arranque."""
        async with self._lock:
            await self._shutdown_locked()

    # ------------------------------------------------------------ navegación
    async def search(
        self,
        query: str,
        engine: str = "bing",
        top_k: int = 10,
    ) -> list[dict[str, str]]:
        """Búsqueda compatible: devuelve sólo los resultados normalizados."""
        report = await self.search_detailed(query, engine=engine, top_k=top_k)
        return report["results"]

    async def search_detailed(
        self,
        query: str,
        engine: str = "bing",
        top_k: int = 10,
    ) -> dict[str, Any]:
        """Busca en un índice y conserva el motivo si no hay resultados utilizables."""
        query = (query or "").strip()
        if not query:
            raise ValueError("Consulta vacía")
        top_k = max(1, min(int(top_k), 20))

        if engine == "bing":
            url = f"https://www.bing.com/search?q={quote_plus(query)}"
            parse = _BING_PARSE
        elif engine == "ddg":
            url = f"https://html.duckduckgo.com/html/?q={quote_plus(query)}"
            parse = _DDG_PARSE
            markup_selector = "a.result__a"
        elif engine == "google":
            url = f"https://www.google.com/search?q={quote_plus(query)}&hl=es"
            parse = _GOOGLE_PARSE
            markup_selector = "div.g, div[data-sokoban-container]"
        else:
            raise ValueError(f"Motor de búsqueda no soportado: {engine}")

        if engine == "bing":
            markup_selector = "li.b_algo"

        try:
            await self._ensure()
            page = await self._context.new_page()
            try:
                response = await page.goto(
                    url, timeout=SEARCH_TIMEOUT_MS, wait_until="domcontentloaded"
                )
                await asyncio.sleep(SETTLE_DELAY_S + random.uniform(0.1, 0.9))
                if blocked := await self._looks_blocked(page, search_page=True):
                    return {"status": "blocked", "reason": blocked, "results": []}
                status_code = response.status if response else 0
                if status_code >= 400:
                    return {
                        "status": "error",
                        "reason": f"http_{status_code}",
                        "results": [],
                    }
                raw = await page.evaluate(parse)
                if not isinstance(raw, list):
                    return {
                        "status": "parse_error",
                        "reason": "El parser no devolvió una lista de resultados",
                        "results": [],
                    }
                results = self._dedupe(raw)[:top_k]
                if results:
                    return {"status": "results", "results": results}

                matching_nodes = await page.locator(markup_selector).count()
                body = await page.evaluate(
                    "() => (document.body ? document.body.innerText.slice(0, 1200).toLowerCase() : '')"
                )
                if matching_nodes:
                    return {
                        "status": "parse_error",
                        "reason": "La página contiene resultados, pero el parser no extrajo ninguno",
                        "results": [],
                    }
                if any(
                    marker in body
                    for marker in (
                        "no results",
                        "no results found",
                        "there are no results",
                        "sin resultados",
                        "no se han encontrado resultados",
                    )
                ):
                    return {"status": "no_results", "results": []}
                return {
                    "status": "empty_or_unrecognized_page",
                    "reason": "La página no muestra resultados ni un mensaje de búsqueda vacía",
                    "results": [],
                }
            finally:
                with contextlib.suppress(Exception):
                    await page.close()
        except Exception as exc:
            logger.warning("stealth-browser: search falló: %s", exc)
            try:
                await self._restart()
            except RuntimeError as rb:
                logger.warning("stealth-browser: %s", rb)
            return {"status": "error", "reason": str(exc), "results": []}

    async def navigate_and_snapshot(
        self,
        url: str,
        timeout_s: float = 30.0,
    ) -> dict[str, Any]:
        """Navega y extrae {title,url,text,links}. Lanza si el sitio es inaccesible."""
        url = (url or "").strip()
        if not re.match(r"^https?://", url, re.IGNORECASE):
            raise ValueError(f"Sólo se permite navegar a http(s): {url}")
        assert_public_http_url(url)  # C2: sin loopback/privada/link-local
        timeout_ms = max(1_000, min(int(float(timeout_s) * 1000), 120_000))

        for attempt in (1, 2):
            try:
                await self._ensure()
                page = await self._context.new_page()
                try:
                    await page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
                    await self._settle_like_human(page)
                    snap: dict[str, Any] = await page.evaluate(_SNAPSHOT_SCRIPT)
                finally:
                    with contextlib.suppress(Exception):
                        await page.close()
                snap["text"] = (snap.get("text") or "")[:SNAPSHOT_MAX_CHARS]
                return snap
            except Exception as exc:
                logger.warning("stealth-browser: navigate falló (intento %d): %s", attempt, exc)
                await self._restart()
        raise RuntimeError(f"No se pudo navegar a {url} tras el reinicio del navegador")

    # ------------------------------------------------- navegación avanzada OSINT
    async def _settle_like_human(self, page: Any) -> None:
        """Pausa no determinista tras cargar: los bots pausan tiempos exactos."""
        await asyncio.sleep(SETTLE_DELAY_S + random.uniform(0.1, 0.9))

    async def _looks_blocked(self, page: Any, *, search_page: bool = False) -> str | None:
        """Detecta páginas de bloqueo comunes (CAPTCHA, WAF, rate-limit). Devuelve razón o None."""
        try:
            url = page.url or ""
            path = urlsplit(url).path.lower()
            if "/sorry/" in path or "challenge" in path or "captcha" in path:
                return "captcha_redirect"
            title = (await page.title()).lower()
            if any(
                w in title
                for w in ("attention required", "access denied", "just a moment", "unusual traffic")
            ):
                return "blocked_page"
            body = await page.evaluate(
                "() => (document.body ? document.body.innerText.slice(0, 500).toLowerCase() : '')"
            )
            markers = [
                "unusual traffic",
                "verify you are human",
                "are you a robot",
                "access to this page has been denied",
            ]
            if not search_page:
                markers.extend(("captcha", "cloudflare"))
            if any(marker in body for marker in markers):
                return "blocked_content"
        except Exception:
            return None
        return None

    async def navigate(
        self,
        url: str,
        timeout_s: float = 30.0,
    ) -> dict[str, Any]:
        """Navega y devuelve {title,url,status,blocked}. SIN extraer contenido:
        para eso está `navigate_and_snapshot`. Registra bloqueos para decisiones del agente."""
        url = (url or "").strip()
        if not re.match(r"^https?://", url, re.IGNORECASE):
            raise ValueError(f"Sólo se permite navegar a http(s): {url}")
        assert_public_http_url(url)  # C2: sin loopback/privada/link-local
        timeout_ms = max(1_000, min(int(float(timeout_s) * 1000), 120_000))

        try:
            await self._ensure()
            page = await self._context.new_page()
            try:
                resp = await page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
                await self._settle_like_human(page)
                blocked = await self._looks_blocked(page)
                return {
                    "title": await page.title(),
                    "url": page.url,
                    "status": resp.status if resp else 0,
                    "blocked": blocked,
                }
            finally:
                with contextlib.suppress(Exception):
                    await page.close()
        except Exception as exc:
            logger.warning("stealth-browser: navigate falló: %s", exc)
            try:
                await self._restart()
            except RuntimeError as rb:
                logger.warning("stealth-browser: %s", rb)
            raise

    async def screenshot(
        self,
        url: str | None = None,
        full_page: bool = False,
        timeout_s: float = 30.0,
    ) -> dict[str, Any]:
        """Captura PNG de la página (navegando primero si se pasa `url`).

        Devuelve {image_base64, mime, title, url, captured_at, fingerprint}.
        Evidencia visual para la cadena de custodia: la sella `browser_osint`.
        """
        import base64

        timeout_ms = max(1_000, min(int(float(timeout_s) * 1000), 120_000))
        try:
            await self._ensure()
            page = await self._context.new_page()
            try:
                if url:
                    if not re.match(r"^https?://", url, re.IGNORECASE):
                        raise ValueError(f"Sólo se permite navegar a http(s): {url}")
                    assert_public_http_url(url)  # C2: sin loopback/privada/link-local
                    await page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
                await self._settle_like_human(page)
                png = await page.screenshot(full_page=full_page, type="png")
                return {
                    "image_base64": base64.b64encode(png).decode("ascii"),
                    "mime": "image/png",
                    "title": await page.title(),
                    "url": page.url,
                    "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "fingerprint": self._fingerprint["label"],
                }
            finally:
                with contextlib.suppress(Exception):
                    await page.close()
        except Exception as exc:
            logger.warning("stealth-browser: screenshot falló: %s", exc)
            raise

    async def interact(
        self,
        url: str,
        actions: list[dict[str, Any]],
        timeout_s: float = 30.0,
    ) -> dict[str, Any]:
        """Secuencia de interacción humana sobre la página y extracción final.

        `actions` es una lista ordenada de pasos:
          {"action": "click",  "selector": "button[type=submit]"}
          {"action": "fill",   "selector": "input[name=q]", "text": "..."}
          {"action": "press",  "key": "Enter"}
          {"action": "wait",   "ms": 1500}
          {"action": "scroll", "delta_y": 600}
        Entre pasos hay pausa humana aleatoria (los bots actúan en µs).
        """
        url = (url or "").strip()
        if not re.match(r"^https?://", url, re.IGNORECASE):
            raise ValueError(f"Sólo se permite navegar a http(s): {url}")
        timeout_ms = max(1_000, min(int(float(timeout_s) * 1000), 120_000))

        try:
            await self._ensure()
            page = await self._context.new_page()
            try:
                await page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
                await self._settle_like_human(page)

                for step in actions or []:
                    act = step.get("action")
                    if act == "click":
                        await page.click(step["selector"], timeout=5_000)
                    elif act == "fill":
                        # Escritura con ritmo humano: delay por tecla.
                        await page.type(
                            step["selector"],
                            str(step.get("text", "")),
                            timeout=5_000,
                            delay=random.randint(40, 130),
                        )
                    elif act == "press":
                        await page.keyboard.press(str(step.get("key", "Enter")))
                    elif act == "wait":
                        await asyncio.sleep(max(0.1, min(float(step.get("ms", 1000)) / 1000, 30)))
                    elif act == "scroll":
                        await page.mouse.wheel(0, int(step.get("delta_y", 600)))
                    else:
                        raise ValueError(f"Acción desconocida: {act!r}")
                    await asyncio.sleep(random.uniform(0.2, 0.8))

                await asyncio.sleep(SETTLE_DELAY_S)
                blocked = await self._looks_blocked(page)
                snap: dict[str, Any] = await page.evaluate(_SNAPSHOT_SCRIPT)
                snap["blocked"] = blocked
                snap["text"] = (snap.get("text") or "")[:SNAPSHOT_MAX_CHARS]
                return snap
            finally:
                with contextlib.suppress(Exception):
                    await page.close()
        except Exception as exc:
            logger.warning("stealth-browser: interact falló: %s", exc)
            raise

    # ------------------------------------------------------------- utilidades
    @staticmethod
    def _dedupe(results: list[dict[str, Any]]) -> list[dict[str, str]]:
        seen: set[str] = set()
        out: list[dict[str, str]] = []
        for r in results or []:
            value = r.get("url") or ""
            if value and value not in seen:
                seen.add(value)
                out.append(
                    {
                        "title": (r.get("title") or "").strip(),
                        "url": value,
                        "snippet": (r.get("snippet") or "").strip(),
                    }
                )
        return out


_manager: StealthBrowser | None = None


async def get_browser() -> StealthBrowser:
    """Instancia única del navegador para todo el engine."""
    global _manager
    if _manager is None:
        _manager = StealthBrowser()
    return _manager
