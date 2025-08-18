(function(){
  const meta = document.querySelector('meta[name="app-base-url"]');
  const base = meta ? meta.content : '';
  const startBtn   = document.getElementById('startBtn');
  const linkStep   = document.getElementById('linkStep');
  const codeDisplay= document.getElementById('codeDisplay');
  const copyBtn    = document.getElementById('copyBtn');
  const statusEl   = document.getElementById('status');

  let currentCode = null;
  let pollTimer   = null;

  async function startAuthClickHandler(){
    try {
      const res = await fetch(`${base}/auth/start.json`, {
        method: 'POST',
        credentials: 'include'
      });
      if (!res.ok) throw new Error('start failed');
      const { code, linkUrl, pollUrl } = await res.json();
      currentCode = code;

      // reveal UI
      linkStep.style.display = 'block';
      codeDisplay.textContent = code;

      // open plex.tv/link in same gesture (avoids popup blocker)
      try { window.open(linkUrl, '_blank', 'noopener'); } catch(e) {}

      // attempt clipboard copy
      await copyCode();

      // start polling
      startPolling(pollUrl);
    } catch (e) {
      if (statusEl) statusEl.textContent = 'Failed to initiate sign-in. Please try again.';
    }
  }

  async function copyCode(){
    if (!currentCode) return;
    try {
      await navigator.clipboard.writeText(currentCode);
      statusEl.textContent = 'Code copied. Enter it on plex.tv/link. Waiting for confirmation…';
    } catch (e) {
      statusEl.textContent = 'Please copy the code and enter it on plex.tv/link. Waiting for confirmation…';
    }
  }

  function startPolling(pollUrl){
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(async () => {
      try {
        const res = await fetch(pollUrl, { credentials: 'include' });
        if (res.status === 200) {
          clearInterval(pollTimer);
          statusEl.innerHTML = "<span class='ok'>Linked! Redirecting to portal…</span>";
          setTimeout(() => { window.location = `${base}/portal`; }, 400);
        } else if (res.status === 202) {
          // pending; keep polling
        } else if (res.status === 404) {
          statusEl.innerHTML = "<span class='warn'>Code not found or expired. Reload and try again.</span>";
          clearInterval(pollTimer);
        } else {
          // temporary error; keep polling
        }
      } catch (e) {
        // network hiccup; ignore
      }
    }, 2000);
  }

  if (startBtn) startBtn.addEventListener('click', startAuthClickHandler);
  if (copyBtn)  copyBtn.addEventListener('click', copyCode);
})();