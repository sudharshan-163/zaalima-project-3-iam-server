const state = {
  csrfToken: null,
  csrfHeader: 'X-CSRF-TOKEN'
};

const sections = document.querySelectorAll('.page-section');
const navItems = document.querySelectorAll('.nav-item');
const pageTitle = document.querySelector('.topbar h1');

function setActiveSection(targetId) {
  const targetSection = document.getElementById(targetId);
  if (!targetSection || !targetSection.classList.contains('page-section')) {
    return;
  }

  sections.forEach((section) => {
    section.classList.toggle('active', section.id === targetId);
  });

  navItems.forEach((button) => {
    button.classList.toggle('active', button.dataset.target === targetId);
  });

  const labels = {
    overview: 'Overview',
    profile: 'Profile',
    registration: 'Registration',
    security: 'Security / MFA'
  };

  if (pageTitle) {
    pageTitle.textContent = labels[targetId] || targetSection.querySelector('h2')?.textContent || 'Overview';
  }
}

navItems.forEach((button) => {
  button.addEventListener('click', () => {
    setActiveSection(button.dataset.target);
    if (button.dataset.target === 'profile') {
      loadCurrentUser();
    }
  });
});

function showStatus(elementId, message, type = 'info') {
  const el = document.getElementById(elementId);
  if (!el) return;
  el.textContent = message;
  el.classList.remove('hidden', 'info', 'success', 'error');
  el.classList.add(type);
  if (message) {
    el.classList.remove('hidden');
  } else {
    el.classList.add('hidden');
  }
}

async function getCsrfToken() {
  try {
    const response = await fetch('/api/csrf', {
      method: 'GET',
      credentials: 'same-origin',
      headers: {
        'Accept': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error('Unable to load CSRF token');
    }

    const data = await response.json();
    const headerName = data && data.headerName ? data.headerName : 'X-CSRF-TOKEN';
    const token = data && data.token ? data.token : null;

    state.csrfToken = token;
    state.csrfHeader = headerName;
    return token;
  } catch (error) {
    console.warn('CSRF unavailable:', error);
    return null;
  }
}

function buildCsrfHeaders(init = {}) {
  const headers = new Headers(init.headers || {});
  if (state.csrfToken) {
    headers.set(state.csrfHeader, state.csrfToken);
  }
  return headers;
}

async function apiFetch(url, options = {}) {
  const method = (options.method || 'GET').toUpperCase();
  const isStateChanging = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);

  let csrfHeaders = {};
  if (isStateChanging) {
    if (!state.csrfToken) {
      await getCsrfToken();
    }
    csrfHeaders = {
      [state.csrfHeader]: state.csrfToken || ''
    };
  }

  const finalHeaders = buildCsrfHeaders({
    headers: {
      ...(options.headers || {}),
      ...csrfHeaders,
      'Accept': 'application/json'
    }
  });

  if (!(options.body instanceof FormData) && !finalHeaders.has('Content-Type') && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
    finalHeaders.set('Content-Type', 'application/json');
  }

  return fetch(url, {
    ...options,
    method,
    headers: finalHeaders,
    credentials: 'same-origin'
  });
}

function parseErrorMessage(payload, fallback) {
  if (!payload) return fallback;
  if (typeof payload === 'string') return payload;
  if (typeof payload === 'object') {
    if (payload.message) return payload.message;
    if (payload.error) return payload.error;
    if (payload.errors) {
      const firstError = Object.values(payload.errors)[0];
      if (Array.isArray(firstError)) return firstError[0];
      if (typeof firstError === 'string') return firstError;
    }
  }
  return fallback;
}

async function loadCurrentUser() {
  const loading = document.getElementById('profile-loading');
  const empty = document.getElementById('profile-empty');
  const form = document.getElementById('profile-form');
  if (loading) loading.classList.remove('hidden');
  if (empty) empty.classList.add('hidden');
  if (form) form.classList.add('hidden');

  try {
    const response = await apiFetch('/api/users/me');
    if (!response.ok) {
      const payload = await response.json().catch(() => null);
      throw new Error(parseErrorMessage(payload, 'User profile is not available.'));
    }

    const user = await response.json();
    fillProfileForm(user);
    if (form) form.classList.remove('hidden');
    showStatus('profile-message', 'Profile loaded successfully.', 'success');
    return user;
  } catch (error) {
    if (empty) empty.classList.remove('hidden');
    showStatus('profile-message', error.message || 'Unable to load profile.', 'error');
    console.error(error);
    return null;
  } finally {
    if (loading) loading.classList.add('hidden');
  }
}

function fillProfileForm(user) {
  if (!user) return;
  const fields = {
    id: document.getElementById('profile-id'),
    enabled: document.getElementById('profile-enabled'),
    username: document.getElementById('profile-username'),
    email: document.getElementById('profile-email')
  };

  Object.entries(fields).forEach(([key, input]) => {
    if (!input) return;
    const value = user[key] ?? '';
    input.value = value;
  });
}

function getProfilePayload(form) {
  return {
    username: form.elements.namedItem('username')?.value ?? document.getElementById('profile-username')?.value ?? '',
    email: form.elements.namedItem('email')?.value ?? document.getElementById('profile-email')?.value ?? ''
  };
}

async function updateProfile(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const payload = getProfilePayload(form);

  try {
    const response = await apiFetch('/api/users/me', {
      method: 'PUT',
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      const payloadError = await response.json().catch(() => null);
      throw new Error(parseErrorMessage(payloadError, 'Unable to update profile.'));
    }

    const result = await response.json().catch(() => null);
    showStatus('profile-message', 'Profile updated successfully.', 'success');
    if (result) {
      fillProfileForm(result);
    } else {
      await loadCurrentUser();
    }
  } catch (error) {
    showStatus('profile-message', error.message || 'Profile update failed.', 'error');
    console.error(error);
  }
}

async function handleRegistration(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const username = document.getElementById('register-username');
  const email = document.getElementById('register-email');
  const password = document.getElementById('register-password');
  if (!username || !email || !password) {
    showStatus('register-message', 'Registration form is unavailable.', 'error');
    return;
  }

  const payload = {
    username: username.value.trim(),
    email: email.value.trim(),
    password: password.value
  };

  if (!payload.username || !payload.email || !payload.password) {
    showStatus('register-message', 'Please complete all required fields.', 'error');
    return;
  }

  try {
    const response = await apiFetch('/api/users/register', {
      method: 'POST',
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      const errorPayload = await response.json().catch(() => null);
      throw new Error(parseErrorMessage(errorPayload, 'Registration failed.'));
    }

    const result = await response.json().catch(() => ({ message: 'Registration succeeded.' }));
    showStatus('register-message', result.message || 'Registration succeeded.', 'success');
    form.reset();
  } catch (error) {
    showStatus('register-message', error.message || 'Registration failed.', 'error');
    console.error(error);
  }
}

async function callMfaEndpoint(endpoint, options = {}) {
  const response = await apiFetch(endpoint, {
    method: options.method || 'POST',
    body: options.body ? JSON.stringify(options.body) : undefined
  });

  if (!response.ok) {
    const errorPayload = options.responseText
      ? await response.text().catch(() => null)
      : await response.json().catch(() => null);
    throw new Error(parseErrorMessage(errorPayload, 'MFA request failed.'));
  }

  if (options.responseText) {
    return response.text();
  }

  return response.json().catch(() => ({ message: 'Request completed successfully.' }));
}

async function setupMfa() {
  const secretBox = document.getElementById('mfa-secret-output');
  if (secretBox) {
    secretBox.textContent = '';
    secretBox.classList.add('hidden');
  }

  try {
    const secret = await callMfaEndpoint('/api/mfa/setup', { responseText: true });
    if (typeof secret !== 'string' || !secret.trim()) {
      throw new Error('MFA setup could not be confirmed because the backend returned no secret.');
    }

    if (secretBox) {
      secretBox.textContent = secret.trim();
      secretBox.classList.remove('hidden');
    }

    showStatus('mfa-message', 'MFA setup completed.', 'success');
  } catch (error) {
    showStatus('mfa-message', error.message || 'Unable to set up MFA.', 'error');
    console.error(error);
  }
}

async function verifyMfa() {
  const codeInput = document.getElementById('mfa-code');
  if (!codeInput) return;
  const code = codeInput.value.trim();
  if (!code) {
    showStatus('mfa-message', 'Please enter an MFA code to verify.', 'error');
    return;
  }

  try {
    const result = await callMfaEndpoint('/api/mfa/verify', {
      method: 'POST',
      body: { code }
    });
    showStatus('mfa-message', result.message || 'MFA verification completed.', 'success');
  } catch (error) {
    showStatus('mfa-message', error.message || 'MFA verification failed.', 'error');
    console.error(error);
  }
}

async function enableMfa() {
  const codeInput = document.getElementById('mfa-code');
  if (!codeInput) {
    showStatus('mfa-message', 'MFA code input is unavailable.', 'error');
    return;
  }

  const code = codeInput.value.trim();
  if (!/^\d{6}$/.test(code)) {
    showStatus('mfa-message', 'Enter a valid six-digit MFA code to enable MFA.', 'error');
    return;
  }

  try {
    const result = await callMfaEndpoint('/api/mfa/enable', {
      method: 'POST',
      body: { code },
      responseText: true
    });
    showStatus('mfa-message', result.trim() || 'MFA enable response was empty.', result.trim() ? 'success' : 'error');
  } catch (error) {
    showStatus('mfa-message', error.message || 'Unable to enable MFA.', 'error');
  }
}

async function disableMfa() {
  try {
    const result = await callMfaEndpoint('/api/mfa/disable');
    showStatus('mfa-message', result.message || 'MFA disabled.', 'success');
  } catch (error) {
    showStatus('mfa-message', error.message || 'Unable to disable MFA.', 'error');
    console.error(error);
  }
}

function addListener(elementId, eventName, handler) {
  const element = document.getElementById(elementId);
  if (element) {
    element.addEventListener(eventName, handler);
  }
}

addListener('profile-form', 'submit', updateProfile);
addListener('load-profile-btn', 'click', loadCurrentUser);
addListener('register-form', 'submit', handleRegistration);
addListener('mfa-setup-btn', 'click', setupMfa);
addListener('mfa-verify-btn', 'click', verifyMfa);
addListener('mfa-enable-btn', 'click', enableMfa);
addListener('mfa-disable-btn', 'click', disableMfa);

getCsrfToken();
loadCurrentUser();
