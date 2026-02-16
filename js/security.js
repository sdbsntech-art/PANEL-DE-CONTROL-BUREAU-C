/**
 * Module de sécurité léger - notifications et enregistrement des incidents
 * N'interrompt pas l'expérience utilisateur (pas de redirection ni blocage agressif).
 */
"use strict";

(function () {
    function showNotice() {
        var notice = document.getElementById("securityNotice");
        if (notice) {
            notice.classList.add("show");
            window.setTimeout(function () {
                notice.classList.remove("show");
            }, 3000);
        }
    }

    document.addEventListener("keydown", function (e) {
        if (e.keyCode === 123 ||
            (e.ctrlKey && e.shiftKey && (e.keyCode === 73 || e.keyCode === 74)) ||
            (e.ctrlKey && e.keyCode === 85)) {
            e.preventDefault();
            showNotice();
            return false;
        }
        if (e.ctrlKey && (e.keyCode === 67 || e.keyCode === 86 || e.keyCode === 65)) {
            if (!e.target.matches("input, textarea, select")) {
                e.preventDefault();
                showNotice();
                return false;
            }
        }
    }, true);

    document.addEventListener("contextmenu", function (e) {
        e.preventDefault();
        showNotice();
        return false;
    });
})();
