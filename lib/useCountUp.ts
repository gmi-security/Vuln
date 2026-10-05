"use client";

import { useEffect, useRef, useState } from "react";

// Animates 0 -> value once per value change (ease-out cubic), not a
// continuous ticker. Shared by RiskGauge and KennaStatChip so every
// hero-section number counts up the same way instead of popping in flat.
export function useCountUp(value: number, durationMs = 900): number {
  const [display, setDisplay] = useState(0);
  const fromRef = useRef(0);
  useEffect(() => {
    const from = fromRef.current;
    const to = value;
    const start = performance.now();
    let raf = 0;
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / durationMs);
      const eased = 1 - Math.pow(1 - t, 3);
      setDisplay(from + (to - from) * eased);
      if (t < 1) raf = requestAnimationFrame(tick);
      else fromRef.current = to;
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);
  return display;
}
