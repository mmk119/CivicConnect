(function () {
  function escapeHTML(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function getToken() {
    return localStorage.getItem("token");
  }

  function authHeaders(extraHeaders) {
    const token = getToken();
    return {
      ...(extraHeaders || {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {})
    };
  }

  async function apiRequest(path, options) {
    const response = await fetch(path, {
      credentials: "include",
      ...(options || {})
    });
    const contentType = response.headers.get("content-type") || "";
    const data = contentType.includes("application/json")
      ? await response.json()
      : await response.text();

    if (!response.ok) {
      const message = typeof data === "object"
        ? data.error || data.message || "Request failed."
        : data || "Request failed.";
      const error = new Error(message);
      error.status = response.status;
      error.data = data;
      throw error;
    }

    return data;
  }

  function clearSession() {
    localStorage.removeItem("token");
    localStorage.removeItem("userRole");
    localStorage.removeItem("role");
    localStorage.removeItem("user_id");
    localStorage.removeItem("ngo_id");
    localStorage.removeItem("userName");
    localStorage.removeItem("loggedInUser");
  }

  // ── Custom dialog (replaces native alert/confirm on every page) ──────────
  function ensureDialog() {
    if (document.getElementById("_ccDialogOverlay")) return;
    const el = document.createElement("div");
    el.id = "_ccDialogOverlay";
    el.style.cssText = "display:none;position:fixed;inset:0;z-index:99999;background:rgba(0,0,0,.45);align-items:center;justify-content:center;";
    el.innerHTML = `
      <div style="background:#fff;border-radius:16px;padding:32px 28px 24px;max-width:420px;width:calc(100% - 40px);box-shadow:0 24px 64px rgba(0,0,0,.22);">
        <p id="_ccDialogMsg" style="margin:0 0 24px;font-size:1rem;color:#10253d;line-height:1.55;font-weight:600;"></p>
        <div style="display:flex;gap:10px;justify-content:flex-end;">
          <button id="_ccDialogCancel" style="display:none;min-height:40px;padding:8px 20px;border:1px solid #cdd8e3;border-radius:10px;background:#fff;color:#10253d;font-weight:800;cursor:pointer;">Cancel</button>
          <button id="_ccDialogOk" style="min-height:40px;padding:8px 20px;border:none;border-radius:10px;background:#1285f3;color:#fff;font-weight:800;cursor:pointer;">OK</button>
        </div>
      </div>`;
    document.body.appendChild(el);
  }

  function showAlert(message, onClose) {
    ensureDialog();
    const overlay = document.getElementById("_ccDialogOverlay");
    document.getElementById("_ccDialogMsg").textContent = message;
    document.getElementById("_ccDialogCancel").style.display = "none";
    overlay.style.display = "flex";
    const ok = document.getElementById("_ccDialogOk");
    const handler = () => {
      overlay.style.display = "none";
      ok.removeEventListener("click", handler);
      if (onClose) onClose();
    };
    ok.addEventListener("click", handler);
  }

  function showConfirm(message, onConfirm, onCancel) {
    ensureDialog();
    const overlay = document.getElementById("_ccDialogOverlay");
    document.getElementById("_ccDialogMsg").textContent = message;
    const cancelBtn = document.getElementById("_ccDialogCancel");
    cancelBtn.style.display = "inline-block";
    overlay.style.display = "flex";
    const ok = document.getElementById("_ccDialogOk");
    const cleanup = () => {
      overlay.style.display = "none";
      cancelBtn.style.display = "none";
      ok.removeEventListener("click", okHandler);
      cancelBtn.removeEventListener("click", cancelHandler);
    };
    const okHandler = () => { cleanup(); if (onConfirm) onConfirm(); };
    const cancelHandler = () => { cleanup(); if (onCancel) onCancel(); };
    ok.addEventListener("click", okHandler);
    cancelBtn.addEventListener("click", cancelHandler);
  }

  // Expose globally so any inline script can call showAlert / showConfirm
  window.showAlert = showAlert;
  window.showConfirm = showConfirm;

  window.CivicConnect = {
    ...(window.CivicConnect || {}),
    apiRequest,
    authHeaders,
    clearSession,
    escapeHTML,
    getToken,
    showAlert,
    showConfirm
  };
})();
