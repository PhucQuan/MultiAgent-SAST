"use client";

import { useEffect, useSyncExternalStore } from "react";

export type Theme = "light" | "dark";

export function useTheme() {
  const theme = useSyncExternalStore(
    (notify) => { window.addEventListener("aegis-theme", notify); return () => window.removeEventListener("aegis-theme", notify); },
    () => localStorage.getItem("aegis_theme") === "light" ? "light" : "dark",
    () => "dark" as Theme,
  );
  const setTheme = (next: Theme) => { localStorage.setItem("aegis_theme", next); window.dispatchEvent(new Event("aegis-theme")); };
  useEffect(() => { document.documentElement.classList.toggle("dark", theme === "dark"); }, [theme]);

  const toggleTheme = () => {
    const nextTheme: Theme = theme === "dark" ? "light" : "dark";
    setTheme(nextTheme);
    localStorage.setItem("aegis_theme", nextTheme);
    document.documentElement.classList.toggle("dark", nextTheme === "dark");
  };

  return { theme, toggleTheme, setTheme };
}
