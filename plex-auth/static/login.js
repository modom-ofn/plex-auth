(function(){
  const base = (document.querySelector('meta[name="app-base-url"]')||{}).content || '';
  const btn = document.getElementById('startBtn');

  function openCenteredPopup(url, title){
    const w = 520, h = 680;
    const y = window.top.outerHeight/2 + window.top.screenY - (h/2);
    const x = window.top.outerWidth /2 + window.top.screenX - (w/2);
    return window.open(url, title, `width=${w},height=${h},left=${x},top=${y},resizable,scrollbars`);
  }

  async function startWeb(){
    btn.disabled = true;
    try {
      const res = await fetch(`${base}/auth/start-web`, { method:'POST', credentials:'include' });
      if (!res.ok) throw new Error('start failed');
      const { authUrl } = await res.json();

      const popup = openCenteredPopup(authUrl, 'Plex Login');

      const handler = (evt) => {
        try {
          if (evt.origin !== window.location.origin) return;
          if (evt.data && evt.data.type === 'plex-auth' && evt.data.ok === true) {
            window.removeEventListener('message', handler);
            window.location = `${base}/portal`;
          }
        } catch(e){}
      };
      window.addEventListener('message', handler);
    } catch (e) {
      console.error(e);
      btn.disabled = false;
      alert('Could not start Plex login. Try again.');
    }
  }

  btn && btn.addEventListener('click', startWeb);
})();