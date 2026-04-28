(function () {
  let toastTimer = null;

  function ensureToast() {
    let toast = document.getElementById("app-toast-message");
    if (toast) return toast;

    const style = document.createElement("style");
    style.textContent = `
      .app-toast-message {
        position: fixed;
        right: 24px;
        bottom: 24px;
        z-index: 10000;
        max-width: min(430px, calc(100vw - 32px));
        padding: 16px 18px 16px 48px;
        border-radius: 14px;
        color: #fff;
        background: #10253d;
        box-shadow: 0 18px 44px rgba(8, 35, 60, 0.28);
        font-family: Arial, sans-serif;
        font-size: 0.98rem;
        font-weight: 700;
        line-height: 1.45;
        opacity: 0;
        transform: translateY(18px);
        pointer-events: none;
        transition: opacity 0.24s ease, transform 0.24s ease;
      }

      .app-toast-message::before {
        content: "i";
        position: absolute;
        left: 16px;
        top: 50%;
        transform: translateY(-50%);
        width: 22px;
        height: 22px;
        display: grid;
        place-items: center;
        border-radius: 50%;
        color: #10253d;
        background: #fff;
        font-weight: 900;
        font-family: Georgia, serif;
      }

      .app-toast-message.show {
        opacity: 1;
        transform: translateY(0);
      }

      .app-toast-message.success {
        background: #198754;
      }

      .app-toast-message.error {
        background: #dc3545;
      }

      .app-toast-message.warning {
        background: #c75b00;
      }

      @media (max-width: 640px) {
        .app-toast-message {
          right: 16px;
          left: 16px;
          bottom: 16px;
          max-width: none;
        }
      }
    `;
    document.head.appendChild(style);

    toast = document.createElement("div");
    toast.id = "app-toast-message";
    toast.className = "app-toast-message";
    toast.setAttribute("role", "status");
    toast.setAttribute("aria-live", "polite");
    document.body.appendChild(toast);
    return toast;
  }

  function detectType(message) {
    const text = String(message || "").toLowerCase();
    if (text.includes("success") || text.includes("updated") || text.includes("submitted") || text.includes("sent")) {
      return "success";
    }
    if (text.includes("error") || text.includes("failed") || text.includes("invalid") || text.includes("denied") || text.includes("cannot") || text.includes("could not")) {
      return "error";
    }
    if (text.includes("please") || text.includes("already") || text.includes("expired") || text.includes("required")) {
      return "warning";
    }
    return "info";
  }

  window.showToast = function (message, type) {
    const toast = ensureToast();
    clearTimeout(toastTimer);
    toast.textContent = message;
    toast.className = `app-toast-message ${type || detectType(message)} show`;
    toastTimer = setTimeout(() => {
      toast.classList.remove("show");
    }, 3600);
  };

  window.alert = function (message) {
    window.showToast(message);
  };
})();
