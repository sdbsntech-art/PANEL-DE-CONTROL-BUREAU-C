/**
 * Configuration du Panel Bureau Conseil
 *
 * CHANGER LE MOT DE PASSE ET METTRE À JOUR LE HASH :
 * 1. Choisissez votre nouveau mot de passe (ex. : MonMotDePasse2025!).
 * 2. Ouvrez votre site (index.html) dans le navigateur.
 * 3. Appuyez sur F12 pour ouvrir les outils de développement, onglet "Console".
 * 4. Collez cette ligne (en remplaçant VotreNouveauMotDePasse par votre mot de passe) puis Entrée :
 *
 *    crypto.subtle.digest('SHA-256', new TextEncoder().encode('VotreNouveauMotDePasse')).then(h => console.log(Array.from(new Uint8Array(h)).map(b => b.toString(16).padStart(2,'0')).join('')))
 *
 * 5. La console affiche une longue chaîne de caractères (le hash). Copiez-la.
 * 6. Remplacez ci-dessous la valeur de passwordHash par cette chaîne (entre guillemets).
 * 7. Enregistrez ce fichier (config.js). Votre nouveau mot de passe sera alors actif.
 */
"use strict";

window.ADMIN_CONFIG = {
    email: "seydoubakhayokho1@gmail.com",
    // Numéro de téléphone de l'administrateur (format international si possible)
    phone: "+221773624539",
    // Hash SHA-256 du mot de passe. Mot de passe actuel : "admin@00"
    passwordHash: "1c96f3b6175a6de61cb7a57c8e88e5f8c825d2be41e2d34aa4e06a3eaf508b70"
};

window.COMMISSIONS = [
    "Points Focaux",
    "Commission Administrative",
    "CTC",
    "CIPS",
    "Logistique",
    "Soxnas",
    "Skils academy"
];

// Données initiales des membres (utilisées si aucun localStorage)
window.INITIAL_MEMBERS = [
    { id: 1, prenom: "Cheikh Ahmed tidiane", nom: "Fall", section: "Section 07C", commission: "Points Focaux", fonction: "Membre PF", type: "titulaire", telephone: "+221 78 557 72 29", email: "fallchei099@gmail.com" },
    { id: 2, prenom: "Seydou", nom: "bakhayokho", section: "section 07C", commission: "Commission Administrative", fonction: "Membre CA", type: "titulaire", telephone: "+221 77 362 45 39", email: "seydoubakhayokho1@gmail.com" },
    { id: 3, prenom: "Mouhamed", nom: "Badiane", section: "Section 10C", commission: "CTC", fonction: "membre CTC", type: "titulaire", telephone: "+221 77 769 68 87", email: "metamedzo18@gmail.com" },
    { id: 4, prenom: "Mouhamed", nom: "Mbengue", section: "Section 06C", commission: "Logistique", fonction: "membre Logistique", type: "titulaire", telephone: "+221 76 328 46 57", email: "muhamedmbengue221@gmail.com" },
    { id: 5, prenom: "Mariama", nom: "Niang", section: "Section 10C", commission: "Soxnas", fonction: "membre Soxnas", type: "titulaire", telephone: "+221 78 372 57 01", email: "mariamaniang387@icloud.com" },
    { id: 6, prenom: "Mame moussa", nom: "Fall", section: "Section 05C", commission: "Skils academy", fonction: "membre Skils academy", type: "titulaire", telephone: "+221 78 608 96 39", email: "fmoussa2101@gmail.com" },
    { id: 7, prenom: "Baba abdoul", nom: "Sow", section: "Section 07C", commission: "CIPS", fonction: "membre CIPS", type: "titulaire", telephone: "+221 78 481 08 18", email: "kingbabsvip@gmail.com" },
];
