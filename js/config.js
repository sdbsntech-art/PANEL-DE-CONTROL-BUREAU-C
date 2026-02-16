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
    // Hash SHA-256 du mot de passe. Mot de passe actuel : "admin"
    passwordHash: "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
};

window.COMMISSIONS = [
    "Points Focaux",
    "Commission Administrative",
    "CTC",
    "CIPS",
    "Logistique"
];

// Données initiales des membres (utilisées si aucun localStorage)
window.INITIAL_MEMBERS = [
    { id: 1, prenom: "Amadou", nom: "DIALLO", section: "Section Nord", commission: "Points Focaux", fonction: "Coordinateur Principal", type: "titulaire", telephone: "+221 77 123 45 67", email: "amadou.diallo@example.sn" },
    { id: 2, prenom: "Fatou", nom: "SALL", section: "Section Centre", commission: "Commission Administrative", fonction: "Secrétaire Générale", type: "titulaire", telephone: "+221 76 234 56 78", email: "fatou.sall@example.sn" },
    { id: 3, prenom: "Moussa", nom: "NDIAYE", section: "Section Sud", commission: "CTC", fonction: "Responsable Technique", type: "titulaire", telephone: "+221 77 345 67 89", email: "moussa.ndiaye@example.sn" }
];
