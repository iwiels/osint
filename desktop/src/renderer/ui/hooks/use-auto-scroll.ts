/**
 * useAutoScroll - seguimiento del final de una lista que crece (streaming del
 * agente, traza de herramientas). Portado de
 * `packages/ui/src/hooks/create-auto-scroll.tsx` de opencode.
 *
 * Reglas que resuelve:
 *  - Mientras el agente trabaja, el scroll sigue pegado al fondo.
 *  - Si el analista sube a leer, se pausa el seguimiento y NO se le arrastra
 *    hacia abajo con cada token (y `onUserInteracted` lo puede indicar en UI).
 *  - Los eventos `scroll` que provoca nuestro propio `scrollTo` no cuentan
 *    como interacción (se marcan con `auto`).
 *  - El desplazamiento dentro de una región anidada (`[data-scrollable]`, p.ej.
 *    la salida de una herramienta) no desactiva el seguimiento.
 */

import { useCallback, useEffect, useRef, useState } from "react";

export interface UseAutoScrollOptions {
  /** true mientras llega contenido nuevo (agente trabajando). */
  working: boolean;
  onUserInteracted?: () => void;
  overflowAnchor?: "none" | "auto" | "dynamic";
  /** Distancia al fondo (px) por debajo de la cual seguimos considerando "abajo". */
  bottomThreshold?: number;
}

export interface AutoScrollApi {
  /** Ref para el contenedor con scroll. */
  scrollRef: (el: HTMLElement | null) => void;
  /** Ref para el contenido que crece dentro del contenedor. */
  contentRef: (el: HTMLElement | null) => void;
  onScroll: () => void;
  pause: () => void;
  resume: () => void;
  scrollToBottom: () => void;
  forceScrollToBottom: () => void;
  /** true = el analista se despegó del fondo. */
  userScrolled: boolean;
}

const AUTO_WINDOW_MS = 1500;
const SETTLE_MS = 300;

export function useAutoScroll(options: UseAutoScrollOptions): AutoScrollApi {
  const { working, onUserInteracted, overflowAnchor = "dynamic", bottomThreshold = 10 } = options;

  const scrollEl = useRef<HTMLElement | null>(null);
  const contentEl = useRef<HTMLElement | null>(null);
  const settling = useRef(false);
  const settleTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const auto = useRef<{ top: number; time: number } | null>(null);
  const autoTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [userScrolled, setUserScrolled] = useState(false);
  // Espejo síncrono: los handlers de scroll/observers no pueden esperar a React.
  const userScrolledRef = useRef(false);

  const setPaused = useCallback((paused: boolean) => {
    userScrolledRef.current = paused;
    setUserScrolled(paused);
  }, []);

  const active = useCallback(() => working || settling.current, [working]);

  const distanceFromBottom = (el: HTMLElement) => el.scrollHeight - el.clientHeight - el.scrollTop;
  const canScroll = (el: HTMLElement) => el.scrollHeight - el.clientHeight > 1;

  const markAuto = useCallback((el: HTMLElement) => {
    auto.current = { top: Math.max(0, el.scrollHeight - el.clientHeight), time: Date.now() };
    if (autoTimer.current) clearTimeout(autoTimer.current);
    autoTimer.current = setTimeout(() => {
      auto.current = null;
      autoTimer.current = null;
    }, AUTO_WINDOW_MS);
  }, []);

  const isAuto = useCallback((el: HTMLElement) => {
    const a = auto.current;
    if (!a) return false;
    if (Date.now() - a.time > AUTO_WINDOW_MS) {
      auto.current = null;
      return false;
    }
    return Math.abs(el.scrollTop - a.top) < 2;
  }, []);

  const scrollToBottom = useCallback(
    (force: boolean) => {
      if (!force && !active()) return;
      const el = scrollEl.current;
      if (!el) return;
      if (force && userScrolledRef.current) setPaused(false);
      if (!force && userScrolledRef.current) return;

      const distance = distanceFromBottom(el);
      markAuto(el);
      if (distance < 2) return;
      // El contenido sigue asentándose: mejor salto inmediato que animación.
      el.scrollTop = el.scrollHeight;
    },
    [active, markAuto, setPaused],
  );

  const pause = useCallback(() => {
    const el = scrollEl.current;
    if (!el) return;
    if (!canScroll(el)) {
      if (userScrolledRef.current) setPaused(false);
      return;
    }
    if (userScrolledRef.current) return;
    setPaused(true);
    onUserInteracted?.();
  }, [onUserInteracted, setPaused]);

  const resume = useCallback(() => {
    setPaused(false);
    const el = scrollEl.current;
    if (el) {
      markAuto(el);
      el.scrollTop = el.scrollHeight;
    }
  }, [markAuto, setPaused]);

  const onScroll = useCallback(() => {
    const el = scrollEl.current;
    if (!el) return;

    if (!canScroll(el)) {
      if (userScrolledRef.current) setPaused(false);
      return;
    }
    if (distanceFromBottom(el) < bottomThreshold) {
      if (userScrolledRef.current) setPaused(false);
      return;
    }
    // ¿Lo movimos nosotros? Entonces seguimos pegados al fondo.
    if (!userScrolledRef.current && isAuto(el)) {
      scrollToBottom(false);
      return;
    }
    pause();
  }, [bottomThreshold, isAuto, pause, scrollToBottom, setPaused]);

  // Rueda hacia arriba = intención explícita de leer (salvo scroll anidado).
  const handleWheel = useCallback(
    (event: WheelEvent) => {
      if (event.deltaY >= 0) return;
      const el = scrollEl.current;
      const target = event.target instanceof Element ? event.target : undefined;
      const nested = target?.closest("[data-scrollable]");
      if (el && nested && nested !== el) return;
      pause();
    },
    [pause],
  );

  const scrollRef = useCallback((el: HTMLElement | null) => {
    scrollEl.current = el;
  }, []);

  const contentRef = useCallback((el: HTMLElement | null) => {
    contentEl.current = el;
  }, []);

  // Escuchar la rueda en el propio contenedor (passive: no bloquea el scroll).
  useEffect(() => {
    const el = scrollEl.current;
    if (!el) return;
    el.addEventListener("wheel", handleWheel, { passive: true });
    return () => el.removeEventListener("wheel", handleWheel);
  }, [handleWheel]);

  // overflow-anchor: si el analista está abajo, anclamos arriba para que el
  // contenido nuevo no desplace la vista; si está leyendo, lo dejamos natural.
  useEffect(() => {
    const el = scrollEl.current;
    if (!el) return;
    if (overflowAnchor === "none") el.style.overflowAnchor = "none";
    else if (overflowAnchor === "auto") el.style.overflowAnchor = "auto";
    else el.style.overflowAnchor = userScrolled ? "auto" : "none";
  }, [overflowAnchor, userScrolled, working]);

  // Contenido que crece (streaming): mantener el fondo en el mismo frame.
  useEffect(() => {
    const content = contentEl.current;
    const el = scrollEl.current;
    if (!content || !el || typeof ResizeObserver === "undefined") return;

    const observer = new ResizeObserver(() => {
      if (!canScroll(el)) {
        if (userScrolledRef.current) setPaused(false);
        return;
      }
      if (!active() || userScrolledRef.current) return;
      scrollToBottom(false);
    });
    observer.observe(content);
    return () => observer.disconnect();
  }, [active, scrollToBottom, setPaused]);

  // Cambios en `working`: al empezar, salto al fondo; al terminar, un breve
  // periodo de asentamiento para absorber el último render.
  useEffect(() => {
    settling.current = false;
    if (settleTimer.current) clearTimeout(settleTimer.current);
    settleTimer.current = null;

    if (working) {
      if (!userScrolledRef.current) scrollToBottom(true);
      return;
    }
    settling.current = true;
    settleTimer.current = setTimeout(() => {
      settling.current = false;
    }, SETTLE_MS);
  }, [working, scrollToBottom]);

  useEffect(
    () => () => {
      if (settleTimer.current) clearTimeout(settleTimer.current);
      if (autoTimer.current) clearTimeout(autoTimer.current);
    },
    [],
  );

  return {
    scrollRef,
    contentRef,
    onScroll,
    pause,
    resume,
    scrollToBottom: () => scrollToBottom(false),
    forceScrollToBottom: () => scrollToBottom(true),
    userScrolled,
  };
}
