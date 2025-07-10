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

document.addEventListener('DOMContentLoaded', () => {
  const genBtn    = document.getElementById('generate-serial');
  const repBtn    = document.getElementById('reprint-serial');
  const serialIn  = document.getElementById('serial');

  if (!genBtn || !repBtn || !serialIn) return;

  // 1) Generieren & Drucken
  genBtn.addEventListener('click', async e => {
    e.preventDefault();
    try {
      const resp = await fetch('/generate_serial');
      const data = await resp.json();
      if (data.serial) {
        serialIn.value = data.serial;
        repBtn.style.display = 'inline-block';
      } else {
        alert('Seriennummer konnte nicht generiert werden.');
      }
    } catch (err) {
      console.error(err);
      alert('Fehler beim Generieren der Seriennummer.');
    }
  });

  // 2) Druckauftrag wiederholen
  repBtn.addEventListener('click', async e => {
    e.preventDefault();
    const serial = serialIn.value;
    if (!serial) {
      alert('Keine Seriennummer zum Drucken vorhanden.');
      return;
    }
    try {
      const resp = await fetch('/print_serial', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({serial})
      });
      const data = await resp.json();
      if (!data.success) {
        alert('Druck fehlgeschlagen: ' + (data.error || 'unbekannter Fehler'));
      }
    } catch (err) {
      console.error(err);
      alert('Fehler beim Wiederholungsdruck.');
    }
  });
});
