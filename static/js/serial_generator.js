/**
 * Serial Number Generator with Label Designer Modal
 * Features:
 * - Generate unique serial numbers
 * - Open label designer in modal
 * - Improved UI/UX with loading states
 */

document.addEventListener('DOMContentLoaded', () => {
  const genBtn = document.getElementById('generate-serial-btn');
  const serialInput = document.getElementById('serial');

  if (!genBtn || !serialInput) return;

  genBtn.addEventListener('click', async (e) => {
    e.preventDefault();

    // UI Feedback: Loading state
    const originalHTML = genBtn.innerHTML;
    genBtn.disabled = true;
    genBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Generiere...';

    try {
      const response = await fetch('/generate_serial');

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();

      if (data.serial) {
        // Erfolg: Seriennummer setzen
        serialInput.value = data.serial;

        // Visuelles Feedback
        serialInput.classList.add('border-success');
        setTimeout(() => {
          serialInput.classList.remove('border-success');
        }, 2000);

        // Erfolgs-Feedback auf Button
        genBtn.innerHTML = '<i class="bi bi-check-circle me-1"></i>Generiert!';
        genBtn.classList.add('btn-success');
        genBtn.classList.remove('btn-outline-primary');

        // Label Designer Modal öffnen
        setTimeout(() => {
          if (typeof window.openLabelDesigner === 'function') {
            window.openLabelDesigner(data.serial);
          } else {
            console.error('openLabelDesigner function not found');
          }
        }, 300);

      } else {
        throw new Error('Keine Seriennummer in Response');
      }

    } catch (error) {
      console.error('Fehler beim Generieren:', error);

      // Fehler-Feedback
      genBtn.innerHTML = '<i class="bi bi-exclamation-triangle me-1"></i>Fehler';
      genBtn.classList.add('btn-danger');
      genBtn.classList.remove('btn-outline-primary');

      // Toast Notification (falls Bootstrap Toast verfügbar)
      showToast('error', 'Fehler beim Generieren der Seriennummer', error.message);

    } finally {
      // Reset Button nach 2 Sekunden
      setTimeout(() => {
        genBtn.disabled = false;
        genBtn.innerHTML = originalHTML;
        genBtn.classList.remove('btn-success', 'btn-danger');
        genBtn.classList.add('btn-outline-primary');
      }, 2000);
    }
  });
});

/**
 * Show Toast Notification
 * @param {string} type - 'success', 'error', 'warning', 'info'
 * @param {string} title
 * @param {string} message
 */
function showToast(type, title, message) {
  // Check if toast container exists
  let toastContainer = document.getElementById('toast-container');

  if (!toastContainer) {
    toastContainer = document.createElement('div');
    toastContainer.id = 'toast-container';
    toastContainer.className = 'toast-container position-fixed top-0 end-0 p-3';
    toastContainer.style.zIndex = '9999';
    document.body.appendChild(toastContainer);
  }

  const toastId = 'toast-' + Date.now();
  const bgClass = {
    'success': 'bg-success',
    'error': 'bg-danger',
    'warning': 'bg-warning',
    'info': 'bg-info'
  }[type] || 'bg-secondary';

  const iconClass = {
    'success': 'bi-check-circle',
    'error': 'bi-exclamation-triangle',
    'warning': 'bi-exclamation-circle',
    'info': 'bi-info-circle'
  }[type] || 'bi-info-circle';

  const toastHTML = `
    <div id="${toastId}" class="toast align-items-center text-white ${bgClass} border-0" role="alert" aria-live="assertive" aria-atomic="true">
      <div class="d-flex">
        <div class="toast-body">
          <i class="bi ${iconClass} me-2"></i>
          <strong>${title}</strong>
          ${message ? '<br><small>' + message + '</small>' : ''}
        </div>
        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
      </div>
    </div>
  `;

  toastContainer.insertAdjacentHTML('beforeend', toastHTML);

  const toastElement = document.getElementById(toastId);
  const toast = new bootstrap.Toast(toastElement, {
    autohide: true,
    delay: 5000
  });

  toast.show();

  // Remove toast element after hidden
  toastElement.addEventListener('hidden.bs.toast', () => {
    toastElement.remove();
  });
}
