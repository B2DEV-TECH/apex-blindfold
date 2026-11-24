// APEX Blindfold - code in the page reads the choice (live session of Layer 2, both layers).
//
// Open the Vote page, open the browser console, paste this whole file, press Enter.
// Then choose an option and cast an honest ballot as usual.
//
// It stands for JavaScript that the server ships with the page. It changes nothing: when you press
// the cast button it reads which option is selected and shows it in a red bar at the top of the
// page, before the browser encrypts anything. Code in that position could just as well send it
// somewhere. The ballot itself is cast and counted as usual.
//
// Reload the page to remove it.
(() => {
  const page = document.getElementById('pFlowStepId')?.value;
  if (page && page !== '1') throw new Error('Paste this on the Vote page.');
  document.addEventListener('click', (event) => {
    if (!event.target.closest('#bf-cast')) return;
    const chosen = document.querySelector('.bf-option[aria-checked="true"]');
    const parts = chosen ? ['.bf-option__letter', '.bf-option__label'].map((css) => chosen.querySelector(css)?.textContent.trim()).filter(Boolean) : [];
    let note = document.getElementById('bf-read-note');
    if (!note) {
      note = document.createElement('div');
      note.id = 'bf-read-note';
      note.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:9999;padding:12px;background:#b00020;color:#fff;font:600 16px system-ui';
      document.body.prepend(note);
    }
    note.textContent = `Read by code in the page, before encryption: ${parts.length ? parts.join(' / ') : 'nothing'}`;
  }, true);
  console.log('Installed. Choose an option and cast: the red bar shows what this code read.');
})();
