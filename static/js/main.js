// JavaScript placeholder
document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('generate-serial-btn');
  if (!btn) return;

  btn.addEventListener('click', async () => {
    btn.disabled = true;               // Optional: Button kurz deaktivieren
    btn.innerText = 'Generiere...';

    try {
      const resp = await fetch('/generate_serial');
      const { serial } = await resp.json();
      document.getElementById('serial').value = serial;
      btn.innerText = 'Erfolgreich gedruckt';
    } catch (err) {
      console.error('Fehler:', err);
      btn.innerText = 'Fehler beim Drucken';
    } finally {
      setTimeout(() => {
        btn.disabled = false;
        btn.innerText = 'Generieren & Drucken';
      }, 2000);
    }
  });
});

console.log('JS geladen');
document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('generate-serial-btn');
  if (!btn) return;

  btn.addEventListener('click', async () => {
    btn.disabled = true;               // Optional: Button kurz deaktivieren
    btn.innerText = 'Generiere...';

    try {
      const resp = await fetch('/generate_serial');
      const { serial } = await resp.json();
      document.getElementById('serial').value = serial;
      btn.innerText = 'Erfolgreich gedruckt';
    } catch (err) {
      console.error('Fehler:', err);
      btn.innerText = 'Fehler beim Drucken';
    } finally {
      setTimeout(() => {
        btn.disabled = false;
        btn.innerText = 'Generieren & Drucken';
      }, 2000);
    }
  });
});
