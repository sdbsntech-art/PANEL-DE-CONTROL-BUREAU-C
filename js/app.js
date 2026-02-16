/**
 * Application principale - Panel de Contrôle Bureau Conseil
 * Gestion des membres, dashboard, comptes visiteur, stockage local.
 */
"use strict";

var members = [];
// Base URL for backend APIs (can be overridden by setting window.API_BASE_URL in config)
var API_BASE_URL = window.API_BASE_URL || 'http://localhost:3000';
var editingId = null;
var currentFilter = "tous";
var loginAttempts = 0;
var MAX_ATTEMPTS = 7;
var isAuthenticated = false;
var currentUserRole = "admin"; // "admin" | "visiteur"
var currentVisitorEmail = null; // email du visiteur connecté (pour lookup des privilèges)
var VISITORS_STORAGE_KEY = "bureauConseilVisitors";
var COMPTES_RENDUS_STORAGE_KEY = "bureauConseilComptesRendus";
var MAX_PDF_SIZE = 5 * 1024 * 1024; // 5 Mo

// Privilèges par défaut pour un nouveau visiteur
var DEFAULT_PRIVILEGES = {
    canViewMembers: false,
    canEditMembers: false,
    canExport: false,
    canViewComptesRendus: false
};

function sha256(message) {
    var msgBuffer = new TextEncoder().encode(message);
    return crypto.subtle.digest("SHA-256", msgBuffer).then(function (hashBuffer) {
        var hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(function (b) { return b.toString(16).padStart(2, "0"); }).join("");
    });
}

function loadFromLocalStorage() {
    var saved = localStorage.getItem("bureauConseilMembers");
    members = saved ? JSON.parse(saved) : (window.INITIAL_MEMBERS || []).slice();
}

function saveToLocalStorage() {
    localStorage.setItem("bureauConseilMembers", JSON.stringify(members));
}

function getVisitors() {
    var raw = localStorage.getItem(VISITORS_STORAGE_KEY);
    var visitors = raw ? JSON.parse(raw) : [];
    // Migration : ajouter privileges aux anciens visiteurs
    var changed = false;
    visitors.forEach(function (v) {
        if (!v.privileges) {
            v.privileges = JSON.parse(JSON.stringify(DEFAULT_PRIVILEGES));
            changed = true;
        }
    });
    if (changed) saveVisitors(visitors);
    return visitors;
}

function saveVisitors(visitors) {
    localStorage.setItem(VISITORS_STORAGE_KEY, JSON.stringify(visitors));
}

function getComptesRendus() {
    var raw = localStorage.getItem(COMPTES_RENDUS_STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
}

function saveComptesRendus(data) {
    localStorage.setItem(COMPTES_RENDUS_STORAGE_KEY, JSON.stringify(data));
}

function getCurrentVisitorPrivileges() {
    if (currentUserRole === "admin") return { canViewMembers: true, canEditMembers: true, canExport: true, canViewComptesRendus: true };
    if (!currentVisitorEmail) return DEFAULT_PRIVILEGES;
    var visitors = getVisitors();
    var v = visitors.find(function (x) { return x.email === currentVisitorEmail; });
    if (!v) return DEFAULT_PRIVILEGES;
    return v.privileges || DEFAULT_PRIVILEGES;
}

function applyRoleUI() {
    var roleEl = document.getElementById("loggedUserRole");
    if (roleEl) roleEl.textContent = currentUserRole === "admin" ? "Administrateur" : "Visiteur";
    var adminTabs = document.querySelectorAll(".nav-tab-admin");
    adminTabs.forEach(function (tab) {
        tab.style.display = currentUserRole === "admin" ? "" : "none";
    });
    var priv = getCurrentVisitorPrivileges();
    // Onglets basés sur les privilèges (pour visiteurs)
    var tabViewMembers = document.querySelector(".nav-tab-priv-viewMembers");
    var tabComptesRendus = document.querySelector(".nav-tab-priv-comptesRendus");
    if (tabViewMembers) tabViewMembers.style.display = (currentUserRole === "admin" || priv.canViewMembers) ? "" : "none";
    if (tabComptesRendus) tabComptesRendus.style.display = (currentUserRole === "admin" || priv.canViewComptesRendus) ? "" : "none";
    // Masquer section dépôt comptes rendus pour visiteurs
    var crAdmin = document.getElementById("comptesRendusAdmin");
    if (crAdmin) crAdmin.style.display = currentUserRole === "admin" ? "" : "none";
    // Boutons Gestion des Membres selon privilèges
    var addBtn = document.getElementById("addMemberBtn");
    var exportBtn = document.getElementById("exportBtn");
    var sendEmailBtn = document.getElementById("sendGroupEmailBtn");
    var sendWhatsappBtn = document.getElementById("sendGroupWhatsappBtn");
    if (addBtn) addBtn.style.display = (currentUserRole === "admin" || priv.canEditMembers) ? "" : "none";
    if (exportBtn) exportBtn.style.display = (currentUserRole === "admin" || priv.canExport) ? "" : "none";
    if (sendEmailBtn) sendEmailBtn.style.display = (currentUserRole === "admin" || priv.canEditMembers) ? "" : "none";
    if (sendWhatsappBtn) sendWhatsappBtn.style.display = (currentUserRole === "admin" || priv.canEditMembers) ? "" : "none";
}

function renderVisitors() {
    var list = document.getElementById("visitorsList");
    var countEl = document.getElementById("visitorsCount");
    if (!list) return;
    var visitors = getVisitors();
    if (countEl) countEl.textContent = visitors.length + " compte(s)";
    if (visitors.length === 0) {
        list.innerHTML = "<p class=\"empty-state\" style=\"padding: 30px; color: #999;\">Aucun compte visiteur. Créez-en un avec le formulaire ci-dessus.</p>";
        return;
    }
    list.innerHTML = visitors.map(function (v) {
        var label = (v.nom && v.nom.trim()) ? v.nom.trim() : v.email;
        var privs = v.privileges || DEFAULT_PRIVILEGES;
        var privLabel = [];
        if (privs.canViewMembers) privLabel.push("Membres");
        if (privs.canEditMembers) privLabel.push("Édition");
        if (privs.canExport) privLabel.push("Export");
        if (privs.canViewComptesRendus) privLabel.push("CR");
        var privText = privLabel.length ? " [" + privLabel.join(", ") + "]" : " [Aucun]";
        return "<div class=\"visitor-item\" data-id=\"" + v.id + "\">" +
            "<div class=\"visitor-item-info\"><strong>" + label + "</strong><br><span>" + v.email + "</span><br><small style=\"color:#999;\">Privilèges:" + privText + "</small></div>" +
            "<div><button type=\"button\" class=\"btn-privileges-visitor\" data-id=\"" + v.id + "\">⚙️ Privilèges</button> <button type=\"button\" class=\"btn-remove-visitor\" data-id=\"" + v.id + "\">Supprimer</button></div></div>";
    }).join("");
    list.querySelectorAll(".btn-remove-visitor").forEach(function (btn) {
        btn.addEventListener("click", function () {
            deleteVisitor(parseInt(btn.getAttribute("data-id"), 10));
        });
    });
    list.querySelectorAll(".btn-privileges-visitor").forEach(function (btn) {
        btn.addEventListener("click", function () {
            openPrivilegesModal(parseInt(btn.getAttribute("data-id"), 10));
        });
    });
}

var privilegesEditingId = null;

function openPrivilegesModal(visitorId) {
    var visitors = getVisitors();
    var v = visitors.find(function (x) { return x.id === visitorId; });
    if (!v) return;
    privilegesEditingId = visitorId;
    document.getElementById("privilegesVisitorEmail").textContent = v.email;
    var privs = v.privileges || DEFAULT_PRIVILEGES;
    document.getElementById("privViewMembers").checked = !!privs.canViewMembers;
    document.getElementById("privEditMembers").checked = !!privs.canEditMembers;
    document.getElementById("privExport").checked = !!privs.canExport;
    document.getElementById("privViewComptesRendus").checked = !!privs.canViewComptesRendus;
    document.getElementById("privilegesModal").classList.add("active");
}

function closePrivilegesModal() {
    document.getElementById("privilegesModal").classList.remove("active");
    privilegesEditingId = null;
}

function savePrivileges(e) {
    e.preventDefault();
    if (privilegesEditingId == null) return;
    var visitors = getVisitors();
    var idx = visitors.findIndex(function (x) { return x.id === privilegesEditingId; });
    if (idx === -1) return;
    visitors[idx].privileges = {
        canViewMembers: document.getElementById("privViewMembers").checked,
        canEditMembers: document.getElementById("privEditMembers").checked,
        canExport: document.getElementById("privExport").checked,
        canViewComptesRendus: document.getElementById("privViewComptesRendus").checked
    };
    saveVisitors(visitors);
    renderVisitors();
    closePrivilegesModal();
}

function renderComptesRendus() {
    var list = document.getElementById("comptesRendusList");
    var countEl = document.getElementById("comptesRendusCount");
    if (!list) return;
    var items = getComptesRendus();
    if (countEl) countEl.textContent = items.length + " document(s)";
    if (items.length === 0) {
        list.innerHTML = "<p class=\"empty-state\" style=\"padding: 30px; color: #999;\">Aucun compte rendu. Déposez-en un avec le formulaire ci-dessus (admin).</p>";
        return;
    }
    list.innerHTML = items.map(function (cr) {
        var dateStr = cr.date ? new Date(cr.date).toLocaleDateString("fr-FR") : "-";
        return "<div class=\"compte-rendu-item\" data-id=\"" + cr.id + "\">" +
            "<div class=\"compte-rendu-item-info\"><strong>" + (cr.titre || "Sans titre") + "</strong><br><span>Réunion du " + dateStr + "</span></div>" +
            "<div class=\"compte-rendu-actions\">" +
            "<button type=\"button\" class=\"btn-view-cr\" data-id=\"" + cr.id + "\">👁 Voir</button>" +
            "<button type=\"button\" class=\"btn-download-cr\" data-id=\"" + cr.id + "\">📥 Télécharger</button>" +
            (currentUserRole === "admin" ? "<button type=\"button\" class=\"btn-delete-cr\" data-id=\"" + cr.id + "\">🗑 Supprimer</button>" : "") +
            "</div></div>";
    }).join("");
    list.querySelectorAll(".btn-view-cr").forEach(function (btn) {
        btn.addEventListener("click", function () { viewCompteRendu(parseInt(btn.getAttribute("data-id"), 10)); });
    });
    list.querySelectorAll(".btn-download-cr").forEach(function (btn) {
        btn.addEventListener("click", function () { downloadCompteRendu(parseInt(btn.getAttribute("data-id"), 10)); });
    });
    list.querySelectorAll(".btn-delete-cr").forEach(function (btn) {
        btn.addEventListener("click", function () { deleteCompteRendu(parseInt(btn.getAttribute("data-id"), 10)); });
    });
}

function viewCompteRendu(id) {
    var items = getComptesRendus();
    var cr = items.find(function (x) { return x.id === id; });
    if (!cr || !cr.fileBase64) return;
    var blob = base64ToBlob(cr.fileBase64, "application/pdf");
    var url = URL.createObjectURL(blob);
    window.open(url, "_blank");
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
}

function downloadCompteRendu(id) {
    var items = getComptesRendus();
    var cr = items.find(function (x) { return x.id === id; });
    if (!cr || !cr.fileBase64) return;
    var blob = base64ToBlob(cr.fileBase64, "application/pdf");
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = (cr.filename || cr.titre || "compte-rendu") + ".pdf";
    a.click();
    URL.revokeObjectURL(url);
}

function base64ToBlob(base64, mimeType) {
    var byteStr = atob(base64);
    var arr = new Uint8Array(byteStr.length);
    for (var i = 0; i < byteStr.length; i++) arr[i] = byteStr.charCodeAt(i);
    return new Blob([arr], { type: mimeType });
}

function deleteCompteRendu(id) {
    if (!confirm("Supprimer ce compte rendu ?")) return;
    var items = getComptesRendus().filter(function (x) { return x.id !== id; });
    saveComptesRendus(items);
    renderComptesRendus();
}

function addCompteRendu(titre, date, fileBase64, filename) {
    var items = getComptesRendus();
    var newId = items.length > 0 ? Math.max.apply(null, items.map(function (x) { return x.id; })) + 1 : 1;
    items.push({ id: newId, titre: titre, date: date || null, fileBase64: fileBase64, filename: filename || null });
    saveComptesRendus(items);
    renderComptesRendus();
}

function addVisitor(email, passwordHash, nom) {
    var visitors = getVisitors();
    var newId = visitors.length > 0 ? Math.max.apply(null, visitors.map(function (v) { return v.id; })) + 1 : 1;
    visitors.push({
        id: newId,
        email: email.trim().toLowerCase(),
        passwordHash: passwordHash,
        nom: (nom || "").trim(),
        privileges: JSON.parse(JSON.stringify(DEFAULT_PRIVILEGES))
    });
    saveVisitors(visitors);
    renderVisitors();
}

function deleteVisitor(id) {
    if (!confirm("Supprimer ce compte visiteur ?")) return;
    var visitors = getVisitors().filter(function (v) { return v.id !== id; });
    saveVisitors(visitors);
    renderVisitors();
}

function updateAllStats() {
    var titulaires = members.filter(function (m) { return m.type === "titulaire"; }).length;
    var elargis = members.filter(function (m) { return m.type === "elargi"; }).length;
    var totalEl = document.getElementById("totalMembers");
    var titEl = document.getElementById("titulaires");
    var elEl = document.getElementById("elargis");
    if (totalEl) totalEl.textContent = members.length;
    if (titEl) titEl.textContent = titulaires;
    if (elEl) elEl.textContent = elargis;
    var dTotal = document.getElementById("dashTotalMembers");
    var dTit = document.getElementById("dashTitulaires");
    var dEl = document.getElementById("dashElargis");
    if (dTotal) dTotal.textContent = members.length;
    if (dTit) dTit.textContent = titulaires;
    if (dEl) dEl.textContent = elargis;
}

function renderDashboard() {
    var titulaires = members.filter(function (m) { return m.type === "titulaire"; });
    var elargis = members.filter(function (m) { return m.type === "elargi"; });
    var tbodyTit = document.getElementById("tbodyTitulaires");
    var tbodyEl = document.getElementById("tbodyElargis");
    var countTit = document.getElementById("countTitulaires");
    var countEl = document.getElementById("countElargis");

    if (tbodyTit) {
        tbodyTit.innerHTML = titulaires.map(function (m) {
            return "<tr><td><strong>" + m.prenom + " " + m.nom + "</strong></td><td>" + m.commission + "</td><td>" + m.fonction + "</td><td>" + m.section + "</td><td>" + m.telephone + "</td><td>" + m.email + "</td><td><span class=\"badge badge-titulaire\">Titulaire</span></td></tr>";
        }).join("");
    }
    if (tbodyEl) {
        if (elargis.length > 0) {
            tbodyEl.innerHTML = elargis.map(function (m) {
                return "<tr><td><strong>" + m.prenom + " " + m.nom + "</strong></td><td>" + m.commission + "</td><td>" + m.fonction + "</td><td>" + m.section + "</td><td>" + m.telephone + "</td><td>" + m.email + "</td><td><span class=\"badge badge-elargi\">Élargi</span></td></tr>";
            }).join("");
        } else {
            tbodyEl.innerHTML = "<tr><td colspan=\"7\" style=\"text-align: center; color: #999;\">Aucun membre élargi pour le moment</td></tr>";
        }
    }
    if (countTit) countTit.textContent = titulaires.length + " membres";
    if (countEl) countEl.textContent = elargis.length + " membres";
}

function createMemberCard(member, canEdit) {
    if (canEdit === undefined) canEdit = true;
    var initials = member.prenom.charAt(0) + member.nom.charAt(0);
    var typeLabel = member.type === "titulaire" ? "Titulaire" : "Élargi";
    var selectHtml = canEdit ? "<div class=\"member-select-wrapper\"><input type=\"checkbox\" class=\"member-select\" data-id=\"" + member.id + "\"></div>" : "";
    var actionsHtml = canEdit
        ? "<div class=\"member-actions\"><button class=\"btn-edit\" data-id=\"" + member.id + "\">✏️ Modifier</button><button class=\"btn-delete\" data-id=\"" + member.id + "\">🗑️ Supprimer</button></div>"
        : "";
    return "<div class=\"member-card\">" +
        selectHtml +
        "<div class=\"member-header\"><div class=\"member-avatar\">" + initials + "</div><div class=\"member-info\"><h3>" + member.prenom + " " + member.nom + "</h3><span class=\"member-badge\">" + typeLabel + "</span></div></div>" +
        "<div class=\"member-details\">" +
        "<div class=\"detail-row\"><span class=\"detail-icon\">🏢</span><span class=\"detail-label\">Section:</span><span class=\"detail-value\">" + member.section + "</span></div>" +
        "<div class=\"detail-row\"><span class=\"detail-icon\">📋</span><span class=\"detail-label\">Commission:</span><span class=\"detail-value\">" + member.commission + "</span></div>" +
        "<div class=\"detail-row\"><span class=\"detail-icon\">💼</span><span class=\"detail-label\">Fonction:</span><span class=\"detail-value\">" + member.fonction + "</span></div>" +
        "<div class=\"detail-row\"><span class=\"detail-icon\">📞</span><span class=\"detail-label\">Téléphone:</span><span class=\"detail-value\">" + member.telephone + "</span></div>" +
        "<div class=\"detail-row\"><span class=\"detail-icon\">📧</span><span class=\"detail-label\">Email:</span><span class=\"detail-value\">" + member.email + "</span></div>" +
        "</div>" +
        actionsHtml +
        "</div>";
}

// Return selected member objects from the UI checkboxes
function getSelectedMembers() {
    var checked = Array.prototype.slice.call(document.querySelectorAll('.member-select:checked'));
    var ids = checked.map(function (el) { return parseInt(el.getAttribute('data-id'), 10); });
    if (!ids || ids.length === 0) return [];
    return members.filter(function (m) { return ids.indexOf(m.id) !== -1; });
}

function openGroupModal() {
    var modal = document.getElementById('groupModal');
    if (!modal) return;
    document.getElementById('groupSubject').value = '';
    document.getElementById('groupMessage').value = '';
    modal.classList.add('active');
}

function closeGroupModal() {
    var modal = document.getElementById('groupModal');
    if (!modal) return;
    modal.classList.remove('active');
}

async function sendGroupEmail() {
    var selected = getSelectedMembers();
    if (!selected || selected.length === 0) { alert('Veuillez sélectionner au moins un membre.'); return; }
    var to = selected.map(function (m) { return m.email; }).filter(Boolean);
    if (to.length === 0) { alert('Aucun email valide parmi les membres sélectionnés.'); return; }
    var subject = document.getElementById('groupSubject').value || '(Sans objet)';
    var message = document.getElementById('groupMessage').value || '';
    try {
        var resp = await fetch(API_BASE_URL + '/send-email', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ to: to, subject: subject, message: message })
        });
        var data = await resp.json();
        if (resp.ok && data.ok) {
            alert('Emails envoyés (' + to.length + ')');
            closeGroupModal();
        } else {
            console.error('sendGroupEmail error', data);
            alert('Erreur lors de l\'envoi des emails: ' + (data.error || resp.status));
        }
    } catch (err) {
        console.error(err);
        alert('Erreur réseau lors de l\'envoi des emails');
    }
}

async function sendGroupWhatsapp() {
    var selected = getSelectedMembers();
    if (!selected || selected.length === 0) { alert('Veuillez sélectionner au moins un membre.'); return; }
    var numbers = selected.map(function (m) { return m.telephone; }).filter(Boolean);
    if (numbers.length === 0) { alert('Aucun numéro valide parmi les membres sélectionnés.'); return; }
    var message = document.getElementById('groupMessage').value || '';
    try {
        // Try server-side send (Twilio) first
        var resp = await fetch(API_BASE_URL + '/send-whatsapp', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ numbers: numbers, message: message })
        });
        var data = await resp.json();
        if (resp.ok && data.ok) {
            if (Array.isArray(data.waLinks) && data.waLinks.length > 0) {
                // Open wa.me links as fallback for client
                data.waLinks.forEach(function (l) { window.open(l, '_blank'); });
                alert('Ouverture des conversations WhatsApp dans de nouveaux onglets.');
            } else {
                alert('Messages WhatsApp envoyés via le backend.');
            }
            closeGroupModal();
        } else {
            console.error('sendGroupWhatsapp error', data);
            alert('Erreur lors de l\'envoi WhatsApp: ' + (data.error || resp.status));
        }
    } catch (err) {
        console.error(err);
        // Fallback client-side: open wa.me links
        numbers.forEach(function (n) {
            var normalized = (n || '').replace(/[^0-9]/g, '');
            var url = 'https://wa.me/' + normalized + '?text=' + encodeURIComponent(message);
            window.open(url, '_blank');
        });
        alert('Aucun envoi serveur possible. Ouverture des liens wa.me pour envoi manuel.');
        closeGroupModal();
    }
}

function renderMembers(searchTerm, filter) {
    if (searchTerm === undefined) searchTerm = "";
    if (filter === undefined) filter = currentFilter;
    var content = document.getElementById("content");
    if (!content) return;
    var filtered = members.slice();

    if (searchTerm) {
        var search = searchTerm.toLowerCase();
        filtered = filtered.filter(function (m) {
            return m.prenom.toLowerCase().indexOf(search) !== -1 ||
                m.nom.toLowerCase().indexOf(search) !== -1 ||
                (m.section && m.section.toLowerCase().indexOf(search) !== -1) ||
                (m.commission && m.commission.toLowerCase().indexOf(search) !== -1) ||
                (m.fonction && m.fonction.toLowerCase().indexOf(search) !== -1) ||
                (m.telephone && m.telephone.indexOf(search) !== -1) ||
                (m.email && m.email.toLowerCase().indexOf(search) !== -1);
        });
    }
    if (filter !== "tous") {
        if (filter === "titulaires") filtered = filtered.filter(function (m) { return m.type === "titulaire"; });
        else if (filter === "elargis") filtered = filtered.filter(function (m) { return m.type === "elargi"; });
        else filtered = filtered.filter(function (m) { return m.commission === filter; });
    }

    var grouped = {};
    filtered.forEach(function (member) {
        if (!grouped[member.commission]) grouped[member.commission] = { titulaires: [], elargis: [] };
        grouped[member.commission][member.type === "titulaire" ? "titulaires" : "elargis"].push(member);
    });

    if (filtered.length === 0) {
        content.innerHTML = "<div class=\"empty-state\"><div class=\"empty-state-icon\">🔍</div><h3>Aucun membre trouvé</h3><p>Essayez de modifier vos critères de recherche</p></div>";
        return;
    }

    var canEdit = currentUserRole === "admin" || (getCurrentVisitorPrivileges().canEditMembers);
    var html = "";
    Object.keys(grouped).sort().forEach(function (commission) {
        var data = grouped[commission];
        if (data.titulaires.length > 0) {
            html += "<div class=\"section-title\"><span>" + commission + " - Titulaires</span><span style=\"font-size: 0.8em; color: #667eea;\">" + data.titulaires.length + " membre(s)</span></div><div class=\"member-grid\">" + data.titulaires.map(function (m) { return createMemberCard(m, canEdit); }).join("") + "</div>";
        }
        if (data.elargis.length > 0) {
            html += "<div class=\"section-title\"><span>" + commission + " - Membres Élargis</span><span style=\"font-size: 0.8em; color: #667eea;\">" + data.elargis.length + " membre(s)</span></div><div class=\"member-grid\">" + data.elargis.map(function (m) { return createMemberCard(m, canEdit); }).join("") + "</div>";
        }
    });
    content.innerHTML = html;

    content.querySelectorAll(".btn-edit").forEach(function (btn) {
        btn.addEventListener("click", function () { editMember(parseInt(btn.getAttribute("data-id"), 10)); });
    });
    content.querySelectorAll(".btn-delete").forEach(function (btn) {
        btn.addEventListener("click", function () { deleteMember(parseInt(btn.getAttribute("data-id"), 10)); });
    });
}

function openModal(member) {
    var modal = document.getElementById("memberModal");
    var form = document.getElementById("memberForm");
    if (member) {
        editingId = member.id;
        document.getElementById("modalTitle").textContent = "Modifier le Membre";
        document.getElementById("prenom").value = member.prenom;
        document.getElementById("nom").value = member.nom;
        document.getElementById("section").value = member.section;
        document.getElementById("commission").value = member.commission;
        document.getElementById("fonction").value = member.fonction;
        document.getElementById("type").value = member.type;
        document.getElementById("telephone").value = member.telephone;
        document.getElementById("email").value = member.email;
    } else {
        editingId = null;
        document.getElementById("modalTitle").textContent = "Ajouter un Membre";
        form.reset();
    }
    modal.classList.add("active");
}

function closeModal() {
    var modal = document.getElementById("memberModal");
    var form = document.getElementById("memberForm");
    if (modal) modal.classList.remove("active");
    if (form) form.reset();
    editingId = null;
}

function saveMember(e) {
    e.preventDefault();
    var memberData = {
        prenom: document.getElementById("prenom").value,
        nom: document.getElementById("nom").value,
        section: document.getElementById("section").value,
        commission: document.getElementById("commission").value,
        fonction: document.getElementById("fonction").value,
        type: document.getElementById("type").value,
        telephone: document.getElementById("telephone").value,
        email: document.getElementById("email").value
    };
    if (editingId) {
        var idx = members.findIndex(function (m) { return m.id === editingId; });
        if (idx !== -1) members[idx] = Object.assign({}, members[idx], memberData);
    } else {
        var newId = members.length > 0 ? Math.max.apply(null, members.map(function (m) { return m.id; })) + 1 : 1;
        members.push(Object.assign({ id: newId }, memberData));
    }
    closeModal();
    renderMembers(document.getElementById("searchInput").value, currentFilter);
    updateAllStats();
    renderDashboard();
    saveToLocalStorage();
}

function editMember(id) {
    var member = members.find(function (m) { return m.id === id; });
    if (member) openModal(member);
}

function deleteMember(id) {
    if (confirm("Êtes-vous sûr de vouloir supprimer ce membre ?")) {
        members = members.filter(function (m) { return m.id !== id; });
        renderMembers(document.getElementById("searchInput").value, currentFilter);
        updateAllStats();
        renderDashboard();
        saveToLocalStorage();
    }
}

function exportData() {
    if (currentUserRole !== "admin" && !getCurrentVisitorPrivileges().canExport) {
        alert("Vous n'avez pas le privilège d'exporter les données.");
        return;
    }
    var dataStr = JSON.stringify(members, null, 2);
    var blob = new Blob([dataStr], { type: "application/json" });
    var url = URL.createObjectURL(blob);
    var link = document.createElement("a");
    link.href = url;
    link.download = "bureau_conseil_membres.json";
    link.click();
    URL.revokeObjectURL(url);
}

function setupEventListeners() {
    var searchInput = document.getElementById("searchInput");
    if (searchInput) {
        searchInput.addEventListener("input", function () {
            renderMembers(this.value, currentFilter);
        });
    }
    document.querySelectorAll(".btn-filter").forEach(function (btn) {
        btn.addEventListener("click", function () {
            document.querySelectorAll(".btn-filter").forEach(function (b) { b.classList.remove("active"); });
            this.classList.add("active");
            currentFilter = this.getAttribute("data-filter");
            renderMembers(document.getElementById("searchInput").value, currentFilter);
        });
    });
    var addBtn = document.getElementById("addMemberBtn");
    if (addBtn) addBtn.addEventListener("click", function () { openModal(null); });
    var closeBtn = document.getElementById("closeModal");
    if (closeBtn) closeBtn.addEventListener("click", closeModal);
    var cancelBtn = document.getElementById("cancelBtn");
    if (cancelBtn) cancelBtn.addEventListener("click", closeModal);
    var form = document.getElementById("memberForm");
    if (form) form.addEventListener("submit", saveMember);
    var exportBtn = document.getElementById("exportBtn");
    if (exportBtn) exportBtn.addEventListener("click", exportData);
    var sendGroupEmailBtn = document.getElementById('sendGroupEmailBtn');
    var sendGroupWhatsappBtn = document.getElementById('sendGroupWhatsappBtn');
    if (sendGroupEmailBtn) sendGroupEmailBtn.addEventListener('click', openGroupModal);
    if (sendGroupWhatsappBtn) sendGroupWhatsappBtn.addEventListener('click', openGroupModal);

    var closeGroupBtn = document.getElementById('closeGroupModal');
    var groupCancel = document.getElementById('groupCancel');
    if (closeGroupBtn) closeGroupBtn.addEventListener('click', closeGroupModal);
    if (groupCancel) groupCancel.addEventListener('click', closeGroupModal);
    var groupSendEmail = document.getElementById('groupSendEmail');
    var groupSendWhatsapp = document.getElementById('groupSendWhatsapp');
    if (groupSendEmail) groupSendEmail.addEventListener('click', sendGroupEmail);
    if (groupSendWhatsapp) groupSendWhatsapp.addEventListener('click', sendGroupWhatsapp);
    var modal = document.getElementById("memberModal");
    if (modal) {
        modal.addEventListener("click", function (e) {
            if (e.target === modal) closeModal();
        });
    }
}

function initAfterLogin() {
    loadFromLocalStorage();
    updateAllStats();
    renderDashboard();
    applyRoleUI();
    setupEventListeners();
    renderComptesRendus();
    setupCompteRenduForm();
    setupPrivilegesModal();
    if (currentUserRole === "admin") {
        renderMembers();
        renderVisitors();
        setupVisitorForm();
    } else {
        var priv = getCurrentVisitorPrivileges();
        if (priv.canViewMembers) renderMembers();
    }
}

function setupCompteRenduForm() {
    var form = document.getElementById("compteRenduForm");
    if (!form) return;
    form.addEventListener("submit", function (e) {
        e.preventDefault();
        var titre = (document.getElementById("crTitre") || {}).value || "";
        var date = (document.getElementById("crDate") || {}).value || "";
        var fileInput = document.getElementById("crFile");
        if (!titre || !fileInput || !fileInput.files || !fileInput.files[0]) {
            alert("Veuillez remplir le titre et sélectionner un fichier PDF.");
            return;
        }
        var file = fileInput.files[0];
        if (file.size > MAX_PDF_SIZE) {
            alert("Fichier trop volumineux (max 5 Mo recommandé).");
            return;
        }
        var reader = new FileReader();
        reader.onload = function (ev) {
            var base64 = (ev.target.result || "").split(",")[1];
            if (!base64) { alert("Erreur lors de la lecture du fichier."); return; }
            addCompteRendu(titre, date || null, base64, file.name.replace(/\.pdf$/i, ""));
            form.reset();
            alert("Compte rendu déposé avec succès.");
        };
        reader.readAsDataURL(file);
    });
}

function setupPrivilegesModal() {
    var closeBtn = document.getElementById("closePrivilegesModal");
    var cancelBtn = document.getElementById("privilegesCancel");
    var form = document.getElementById("privilegesForm");
    if (closeBtn) closeBtn.addEventListener("click", closePrivilegesModal);
    if (cancelBtn) cancelBtn.addEventListener("click", closePrivilegesModal);
    if (form) form.addEventListener("submit", savePrivileges);
    var modal = document.getElementById("privilegesModal");
    if (modal) {
        modal.addEventListener("click", function (e) {
            if (e.target === modal) closePrivilegesModal();
        });
    }
}

function setupVisitorForm() {
    var form = document.getElementById("visitorForm");
    if (!form) return;
    form.addEventListener("submit", function (e) {
        e.preventDefault();
        var emailInput = document.getElementById("visitorEmail");
        var passwordInput = document.getElementById("visitorPassword");
        var nameInput = document.getElementById("visitorName");
        var email = (emailInput && emailInput.value) ? emailInput.value.trim() : "";
        var password = (passwordInput && passwordInput.value) ? passwordInput.value : "";
        var nom = (nameInput && nameInput.value) ? nameInput.value.trim() : "";
        if (!email || !password) {
            alert("Veuillez remplir l'email et le mot de passe.");
            return;
        }
        var visitors = getVisitors();
        if (visitors.some(function (v) { return v.email === email.toLowerCase(); })) {
            alert("Un compte visiteur avec cet email existe déjà.");
            return;
        }
        sha256(password).then(function (passwordHash) {
            addVisitor(email, passwordHash, nom);
            form.reset();
        });
    });
}

// Connexion (admin ou visiteur)
document.getElementById("loginForm").addEventListener("submit", function (e) {
    e.preventDefault();
    if (loginAttempts >= MAX_ATTEMPTS) {
        alert("Trop de tentatives échouées. Veuillez réessayer plus tard.");
        return;
    }
    var emailRaw = document.getElementById("adminEmail").value;
    var email = emailRaw ? emailRaw.trim().toLowerCase() : "";
    var password = document.getElementById("adminPassword").value;
    var config = window.ADMIN_CONFIG || {};
    sha256(password).then(function (passwordHash) {
        if (email === (config.email || "").toLowerCase() && passwordHash === config.passwordHash) {
            currentUserRole = "admin";
            currentVisitorEmail = null;
            isAuthenticated = true;
            loginAttempts = 0;
            document.getElementById("loginContainer").style.display = "none";
            document.getElementById("mainContainer").classList.add("active");
            var loggedEl = document.getElementById("loggedAdminEmail");
            if (loggedEl) loggedEl.textContent = emailRaw.trim();
            initAfterLogin();
            return;
        }
        var visitors = getVisitors();
        for (var i = 0; i < visitors.length; i++) {
            if (visitors[i].email === email && visitors[i].passwordHash === passwordHash) {
                currentUserRole = "visiteur";
                currentVisitorEmail = visitors[i].email;
                isAuthenticated = true;
                loginAttempts = 0;
                document.getElementById("loginContainer").style.display = "none";
                document.getElementById("mainContainer").classList.add("active");
                var loggedEl = document.getElementById("loggedAdminEmail");
                if (loggedEl) loggedEl.textContent = (visitors[i].nom && visitors[i].nom.trim()) ? visitors[i].nom.trim() : visitors[i].email;
                initAfterLogin();
                return;
            }
        }
        loginAttempts++;
        var errEl = document.getElementById("errorMessage");
        if (errEl) {
            errEl.classList.add("show");
            window.setTimeout(function () { errEl.classList.remove("show"); }, 3000);
        }
    });
});

document.getElementById("logoutBtn").addEventListener("click", function () {
    if (confirm("Voulez-vous vraiment vous déconnecter ?")) {
        isAuthenticated = false;
        currentUserRole = "admin";
        currentVisitorEmail = null;
        document.getElementById("mainContainer").classList.remove("active");
        document.getElementById("loginContainer").style.display = "block";
        document.getElementById("loginForm").reset();
    }
});

// Navigation onglets
document.querySelectorAll(".nav-tab").forEach(function (tab) {
    tab.addEventListener("click", function () {
        document.querySelectorAll(".nav-tab").forEach(function (t) { t.classList.remove("active"); });
        document.querySelectorAll(".tab-content").forEach(function (c) { c.classList.remove("active"); });
        this.classList.add("active");
        var tabId = this.getAttribute("data-tab");
        var content = document.getElementById(tabId);
        if (content) content.classList.add("active");
    });
});
