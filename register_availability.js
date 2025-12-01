// register_availability.js
// Attach to inputs with IDs: #username, #email, #contact_number
// Each input should have a sibling element with class .availability-status and data-field matching

(() => {
  // Use a relative path so requests target the same folder as register.php (e.g. /NEW/check_availability.php)
  const ENDPOINT = 'check_availability.php';

  const debounce = (fn, wait) => {
    let t = null;
    return (...args) => {
      if (t) clearTimeout(t);
      t = setTimeout(()=> fn(...args), wait);
    };
  };

  const show = (el, text, state) => {
    // state: 'checking' | 'available' | 'taken' | 'error'
    el.classList.remove('text-green-600','text-red-600','text-gray-500','animate-pulse');
    el.textContent = text;
    if (state === 'checking') {
      el.classList.add('text-gray-500','animate-pulse');
    } else if (state === 'available') {
      el.classList.add('text-green-600');
    } else if (state === 'taken') {
      el.classList.add('text-red-600');
    } else {
      el.classList.add('text-gray-500');
    }
  };

  const check = async (field, value, statusEl) => {
    if (!value || value.trim() === '') {
      show(statusEl, '', ''); return;
    }
    show(statusEl, 'Checking…', 'checking');
    try {
      const url = `${ENDPOINT}?field=${encodeURIComponent(field)}&value=${encodeURIComponent(value)}`;
      const res = await fetch(url, { method: 'GET', credentials: 'same-origin' });
      // If 404 or other non-200, show error
      if (!res.ok) {
        console.error('availability request failed, status=', res.status, res.statusText, 'url=', url);
        show(statusEl, 'Error', 'error'); return;
      }
      const json = await res.json();
      if (!json || !json.ok) {
        // If endpoint returns {"ok":false,"error":"..."} show that in console and UI
        console.warn('availability endpoint returned error:', json && json.error);
        show(statusEl, 'Error', 'error'); return;
      }
      if (json.available) {
        show(statusEl, 'Available', 'available');
      } else {
        show(statusEl, 'Taken', 'taken');
      }
    } catch (err) {
      console.error('availability check failed', err);
      show(statusEl, 'Error', 'error');
    }
  };

  const attach = (inputId, fieldName) => {
    const input = document.getElementById(inputId);
    if (!input) return;
    // find status element: prefer data-status-for attribute, else next sibling with .availability-status
    let statusEl = document.querySelector(`[data-status-for="${inputId}"]`);
    if (!statusEl) statusEl = input.parentElement.querySelector('.availability-status');
    if (!statusEl) {
      // create status span
      statusEl = document.createElement('span');
      statusEl.className = 'availability-status ml-2 text-sm';
      input.parentElement.appendChild(statusEl);
    }
    const debounced = debounce((v)=> check(fieldName, v, statusEl), 400);
    input.addEventListener('input', (e) => debounced(e.target.value));
    input.addEventListener('blur', (e) => debounced(e.target.value));
  };

  // Initialization
  document.addEventListener('DOMContentLoaded', function(){
    attach('username','username');
    attach('email','email');
    attach('contact_number','contact_number');
  });
})();