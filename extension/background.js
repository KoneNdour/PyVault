// background.js — Service Worker de l'extension PyVault
// Gère la persistance du token de session et les notifications

const API = "http://127.0.0.1:7890";

// Récupérer le token au démarrage
chrome.runtime.onInstalled.addListener(fetchToken);
chrome.runtime.onStartup.addListener(fetchToken);

async function fetchToken() {
  try {
    const resp = await fetch(`${API}/token`);
    const data = await resp.json();
    await chrome.storage.local.set({ pyvault_token: data.session_token });
    console.log("[PyVault] Token synchronisé depuis le serveur.");
  } catch {
    console.warn("[PyVault] Serveur PyVault non disponible.");
  }
}

// Répondre aux messages du content script
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "GET_TOKEN") {
    chrome.storage.local.get(["pyvault_token"], data => {
      sendResponse({ token: data.pyvault_token || "" });
    });
    return true; // async response
  }
});
