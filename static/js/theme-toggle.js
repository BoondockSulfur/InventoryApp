(() => {
  'use strict';

  const ROOT     = document.documentElement;       // <html>
  const BODY     = document.body;                  // <body>
  const SWITCHES = document.querySelectorAll(
        'input[type="checkbox"]#_theme_toggle, input[data-toggle="theme"]');

  if (!SWITCHES.length) return;                    // falls kein Schalter existiert

  // ─── Hilfsfunktionen ────────────────────────────────────────────
  const systemPrefersDark = () =>
        window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';

  const stored = localStorage.getItem('theme');    // "dark" | "light" | null

  const apply = mode => {
    // 1)  Bootstrap‑5.3‑Schalter  (z. B. btn‑primary wird dunkel)
    ROOT.setAttribute('data-bs-theme', mode);

    // 2)  eigenes Fallback  (falls Du irgendwo `data-theme="dark"` verwendest)
    ROOT.setAttribute('data-theme', mode);

    // 3)  Dein variables CSS  (setzt Farb‑Variablen)
    BODY.classList.toggle('dark-mode', mode === 'dark');

    // 4)  alle Schalter synchron stellen
    SWITCHES.forEach(el => (el.checked = mode === 'dark'));

    // 5)  Auswahl merken
    localStorage.setItem('theme', mode);
  };

  // ─── Initialisieren ────────────────────────────────────────────
  apply(stored || systemPrefersDark());

  // ─── Klick / Touch auf Schalter ────────────────────────────────
  SWITCHES.forEach(el =>
    el.addEventListener('change', () =>
      apply(el.checked ? 'dark' : 'light')));

  // ─── OS‑Theme ändert sich (nur solange kein eigenes Setting gespeichert) ─
  window.matchMedia('(prefers-color-scheme: dark)')
        .addEventListener('change', e => {
          if (!localStorage.getItem('theme')) apply(e.matches ? 'dark' : 'light');
        });
})();
