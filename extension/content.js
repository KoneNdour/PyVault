// content.js — Détection automatique des formulaires de connexion
// Affiche une suggestion de remplissage quand un champ mot de passe est détecté

(async () => {
  const API = "http://127.0.0.1:7890";

  // Récupérer le token depuis le background
  const tokenResp = await chrome.runtime.sendMessage({ type: "GET_TOKEN" });
  const TOKEN = tokenResp?.token || "";
  if (!TOKEN) return;

  // Vérifier que le vault est déverrouillé
  let isUnlocked = false;
  try {
    const r = await fetch(`${API}/api/vault/status`, { headers: { "X-PyVault-Token": TOKEN } });
    const d = await r.json();
    isUnlocked = d.unlocked;
  } catch { return; }

  if (!isUnlocked) return;

  // Trouver les champs de mot de passe
  const pwdFields = document.querySelectorAll('input[type="password"]');
  if (!pwdFields.length) return;

  // Chercher des entrées correspondant à l'URL actuelle
  try {
    const r = await fetch(
      `${API}/api/entries/by-url?url=${encodeURIComponent(window.location.href)}`,
      { headers: { "X-PyVault-Token": TOKEN } }
    );
    const entries = await r.json();
    if (!entries.length) return;

    // Afficher la bannière de suggestion
    showSuggestion(entries, pwdFields[0]);
  } catch { }

  function showSuggestion(entries, pwdField) {
    // Supprimer une bannière précédente
    document.getElementById("pyvault-suggestion")?.remove();

    const banner = document.createElement("div");
    banner.id = "pyvault-suggestion";
    banner.style.cssText = `
      position: fixed; top: 1rem; right: 1rem; z-index: 2147483647;
      background: #1a1d2e; border: 1px solid #6c63ff; border-radius: 10px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.6); padding: .875rem 1rem;
      font-family: 'Segoe UI', system-ui, sans-serif; font-size: 13px;
      color: #e2e8f0; min-width: 240px; max-width: 320px;
    `;

    const header = document.createElement("div");
    header.style.cssText = "display:flex; align-items:center; justify-content:space-between; margin-bottom:.5rem;";
    header.innerHTML = `
      <span style="font-weight:600; color:#a78bfa;">🔒 PyVault</span>
      <button id="pyvault-close" style="background:none;border:none;color:#64748b;cursor:pointer;font-size:16px;">✕</button>
    `;
    banner.appendChild(header);

    const subtitle = document.createElement("p");
    subtitle.style.cssText = "color:#64748b; font-size:11px; margin-bottom:.6rem;";
    subtitle.textContent = `${entries.length} compte(s) disponible(s) pour ce site`;
    banner.appendChild(subtitle);

    entries.slice(0, 3).forEach(entry => {
      const btn = document.createElement("button");
      btn.style.cssText = `
        display:block; width:100%; text-align:left; padding:.5rem .7rem;
        background:#252840; border:1px solid #2a2d4a; border-radius:7px;
        color:#e2e8f0; cursor:pointer; font-size:12px; margin-bottom:.3rem;
        transition: border-color .15s;
      `;
      btn.innerHTML = `<strong>${entry.site_name}</strong><br><span style="color:#94a3b8;">${entry.username}</span>`;
      btn.onmouseover = () => btn.style.borderColor = "#6c63ff";
      btn.onmouseout  = () => btn.style.borderColor = "#2a2d4a";
      btn.onclick     = async () => {
        try {
          const r = await fetch(`${API}/api/entries/${entry.id}`, {
            headers: { "X-PyVault-Token": TOKEN }
          });
          const full = await r.json();

          // Remplir les champs username/email
          const userFields = document.querySelectorAll(
            'input[type="email"], input[type="text"][name*="user"], input[type="text"][name*="email"], input[autocomplete="username"], input[autocomplete="email"]'
          );
          if (userFields.length) {
            userFields[0].focus();
            userFields[0].value = full.username;
            userFields[0].dispatchEvent(new Event("input", { bubbles: true }));
            userFields[0].dispatchEvent(new Event("change", { bubbles: true }));
          }

          // Remplir le mot de passe
          if (pwdField) {
            pwdField.focus();
            pwdField.value = full.password;
            pwdField.dispatchEvent(new Event("input", { bubbles: true }));
            pwdField.dispatchEvent(new Event("change", { bubbles: true }));
          }

          banner.remove();
        } catch (err) {
          console.error("[PyVault] Erreur lors du remplissage :", err);
        }
      };
      banner.appendChild(btn);
    });

    document.body.appendChild(banner);
    document.getElementById("pyvault-close").onclick = () => banner.remove();

    // Auto-disparition après 12 secondes
    setTimeout(() => banner.remove(), 12000);
  }
})();
