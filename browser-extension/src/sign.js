import { decryptVPKey } from "./crypto.js";

(async () => {
  try {
    const stored = await chrome.storage.local.get(["tipKey", "pendingReg"]);
    if (!stored.tipKey) throw new Error("No key found");
    if (!stored.pendingReg) throw new Error("No pending registration");

    const privateKeyHex = await decryptVPKey(stored.tipKey);

    chrome.runtime.sendMessage({
      type: "REGISTER_CONTENT_WITH_KEY",
      payload: { ...stored.pendingReg, privateKeyHex },
    }, (res) => {
      chrome.storage.local.remove("pendingReg");
      chrome.storage.local.set({ signResult: res });
      window.close();
    });
  } catch (e) {
    document.getElementById("error").textContent = e.message;
    document.getElementById("error").style.display = "block";
    document.querySelector(".msg").textContent = "Authentication failed";
  }
})();
