import { decryptVPKey } from "./crypto.js";

(async () => {
  try {
    const stored = await chrome.storage.local.get([
      "tipKey", "pendingReg"
    ]);
    if (!stored.pendingReg) throw new Error("No pending registration");

    // Only VP-connected flow works here (tipKey object)
    // Manual setup users should use the options page Platforms tab
    if (!stored.tipKey || !stored.tipKey.data) {
      throw new Error("Use the extension settings → Platforms tab to register content.");
    }

    document.querySelector(".msg").textContent = "🔐 Tap to authenticate...";

    const privateKeyHex = await decryptVPKey(stored.tipKey);

    document.querySelector(".msg").textContent = "✅ Signing content...";

    chrome.runtime.sendMessage({
      type: "REGISTER_CONTENT_WITH_KEY",
      payload: { ...stored.pendingReg, privateKeyHex },
    }, (res) => {
      chrome.storage.local.remove("pendingReg");
      chrome.storage.local.set({ signResult: res || { ok: false, error: "No response" } });
    });
  } catch (e) {
    console.error("sign.js error:", e);
    chrome.storage.local.remove("pendingReg");
    chrome.storage.local.set({ signResult: { ok: false, error: e.message } });
    if (document.getElementById("error")) {
      document.getElementById("error").textContent = e.message;
      document.getElementById("error").style.display = "block";
    }
    if (document.querySelector(".msg")) {
      document.querySelector(".msg").textContent = "Authentication failed";
    }
  }
})();
