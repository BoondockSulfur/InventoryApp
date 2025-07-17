// static/js/main.js

document.addEventListener('DOMContentLoaded', () => {
  // ─── Seriennummer generieren & drucken ──────────────────────────────────
  const genBtn   = document.getElementById('generate-serial-btn');
  const repBtn   = document.getElementById('reprint-serial-btn');
  const serialIn = document.getElementById('serial');

  // Wiederholungs-Button initial ein- oder ausblenden
  if (serialIn && repBtn) {
    repBtn.style.display = serialIn.value ? 'inline-block' : 'none';
  }

  if (genBtn && repBtn && serialIn) {
    // 1) Generieren & Drucken
    genBtn.addEventListener('click', async e => {
      e.preventDefault();
      genBtn.disabled = true;
      genBtn.innerText = 'Generiere…';
      try {
        const resp = await fetch('/generate_serial');
        const data = await resp.json();
        if (data.serial) {
          serialIn.value = data.serial;
          repBtn.style.display = 'inline-block';
          genBtn.innerText = 'Gedruckt';
        } else {
          genBtn.innerText = 'Fehler';
        }
      } catch (err) {
        console.error('Fehler beim Generieren:', err);
        genBtn.innerText = 'Fehler';
      } finally {
        setTimeout(() => {
          genBtn.disabled = false;
          genBtn.innerText = 'Generieren & Drucken';
        }, 2000);
      }
    });

    // 2) Wiederholungsdruck
    repBtn.addEventListener('click', async e => {
      e.preventDefault();
      const serial = serialIn.value;
      if (!serial) {
        alert('Keine Seriennummer zum Drucken vorhanden.');
        return;
      }
      repBtn.disabled = true;
      repBtn.innerText = 'Drucke…';
      try {
        const resp = await fetch('/print_serial', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({serial})
        });
        const result = await resp.json();
        if (result.success) {
          repBtn.innerText = 'Erneut gedruckt';
        } else {
          repBtn.innerText = 'Fehler';
          console.error('Druck-Fehler:', result.error);
        }
      } catch (err) {
        console.error('Fehler beim Wiederholungsdruck:', err);
        repBtn.innerText = 'Fehler';
      } finally {
        setTimeout(() => {
          repBtn.disabled = false;
          repBtn.innerText = 'Wiederholen';
        }, 2000);
      }
    });
  }
});
