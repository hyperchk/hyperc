(async function () {

    const correctHash = "2af9bef3221be51214fdb77683bd75868a9be643e4d081edb6135cd4d09f5c12";

    const protectedPaths = [
        "/hack-the-box/machines/medium/linux/interpreter/write%20up/"
    ];

    async function sha256(message) {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
    }

    function needsProtection() {
        const currentPath = window.location.pathname.toLowerCase();
        return protectedPaths.some(path =>
            currentPath.includes(path)
        );
    }

    function blockPage() {
        if (!needsProtection()) return;

        // eliminar overlay anterior si existe
        const old = document.getElementById("auth-overlay");
        if (old) old.remove();

        const overlay = document.createElement("div");
        overlay.id = "auth-overlay";
        overlay.innerHTML = `
            <div class="auth-box">
                <h2>Restricted Access</h2>
                <input type="password" id="auth-input" placeholder="Enter password" />
                <button id="auth-btn">Unlock</button>
                <p id="auth-error"></p>
            </div>
        `;

        document.body.appendChild(overlay);

        document.getElementById("auth-btn").onclick = async () => {
            const value = document.getElementById("auth-input").value;
            const inputHash = await sha256(value);

            if (inputHash === correctHash) {
                overlay.remove();
            } else {
                document.getElementById("auth-error").innerText = "Wrong password";
            }
        };
    }

    // 🔥 CLAVE: escuchar cambios SPA de Material
    if (typeof document$ !== "undefined") {
        document$.subscribe(function () {
            blockPage();
        });
    }

    // fallback normal
    window.addEventListener("load", blockPage);

})();