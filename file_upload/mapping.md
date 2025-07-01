# 🗂️ Mapping des Données Excel vers les Modèles Django

Ce document détaille le mapping complet des colonnes d’un fichier Excel statistique vers les modèles de la base de données Django utilisés pour la gestion des remboursements de soins de santé.

---

## 🔖 Sommaire

- [ActCategory](#1-actcategory)
- [ActFamily](#2-actfamily)
- [Act](#3-act)
- [Partner](#4-partner)
- [Client](#5-client)
- [Policy](#6-policy)
- [Insured](#7-insured)
- [InsuredEmployer](#8-insuredemployer)
- [Invoice](#9-invoice)
- [PaymentMethod](#10-paymentmethod)
- [Operator](#11-operator)
- [Claim](#12-claim)
- [Remarques Globales](#13-remarques-globales)

---

## 1. 🟦 ActCategory

| Colonne Excel              | Modèle Django   | Champ Django      | Action                                        |
|---------------------------|-----------------|-------------------|-----------------------------------------------|
| `Categorie d'acte`        | `ActCategory`   | `label`           | Créer si inexistant, sinon réutiliser        |

---

## 2. 🟪 ActFamily

| Colonne Excel              | Modèle Django   | Champ Django      | Action                                        |
|---------------------------|-----------------|-------------------|-----------------------------------------------|
| `Famille Acte`            | `ActFamily`     | `label`           | Créer si inexistant et relier à `ActCategory`|

---

## 3. 🟩 Act

| Colonne Excel              | Modèle Django   | Champ Django      | Action                                        |
|---------------------------|-----------------|-------------------|-----------------------------------------------|
| `Nom Acte`                | `Act`           | `label`           | Créer si inexistant, lier à `ActFamily` + `ActCategory` |

---

## 4. 🟨 Partner

| Colonne Excel              | Modèle Django   | Champ Django      | Action                                        |
|---------------------------|-----------------|-------------------|-----------------------------------------------|
| `Nom du partenaire`       | `Partner`       | `name`            | Créer si inexistant pour le pays             |
| `Pays du partenaire`      | `Partner`       | `country`         | Si vide → utiliser le pays de l’uploader     |

---

## 5. 🟥 Client

| Colonne Excel              | Modèle Django   | Champ Django      | Action                                        |
|---------------------------|-----------------|-------------------|-----------------------------------------------|
| `Nom Employeur`           | `Client`        | `name`            | Créer si inexistant pour le pays de l’uploader |

---

## 6. 🔷 Policy

| Colonne Excel              | Modèle Django   | Champ Django      | Action                                        |
|---------------------------|-----------------|-------------------|-----------------------------------------------|
| `Numero de police`        | `Policy`        | `policy_number`   | Créer si inexistant et lier au `Client`      |

---

## 7. 🟧 Insured

| Colonne Excel              | Modèle Django   | Champ Django      | Action                                        |
|---------------------------|-----------------|-------------------|-----------------------------------------------|
| `Nom bénéficiaire`        | `Insured`       | `name`            | Créer si inexistant                           |
| `Statut Assuré`           | `Insured`       | is_*              | `A` → principal, `C` → conjoint, `E` → enfant |
| `Nom Assuré Principal`    | `Insured`       | `primary_insured` | FK vers un autre `Insured`                   |

---

## 8. 🟫 InsuredEmployer

| Donnée dérivée            | Modèle Django   | Champ Django      | Action                                        |
|---------------------------|-----------------|-------------------|-----------------------------------------------|
| `Nom bénéficiaire`        | `InsuredEmployer` | `insured`        | Lier                                          |
| `Nom Employeur`           |                 | `employer`        | Lier à `Client`                               |
| `Numero de police`        |                 | `policy`          | Lier à `Policy`                               |
| `Statut Assuré`           |                 | `role`            | Converti en role (`primary`, `spouse`, `child`) |
| `Nom Assuré Principal`    |                 | `primary_insured_ref` | FK conditionnel                             |

---

## 9. 📄 Invoice

| Colonne Excel              | Modèle Django   | Champ Django      | Action                                        |
|---------------------------|-----------------|-------------------|-----------------------------------------------|
| `Numero de Facture`       | `Invoice`       | `invoice_number`  | Créer si inexistant                           |
| `Montant facturé`         |                 | `claimed_amount`  | Valeur brute                                  |
| `Montant remboursé`       |                 | `reimbursed_amount`| Valeur nette                                  |
| `Nom bénéficiaire`        |                 | `insured`         | FK vers `Insured`                             |
| `Nom du partenaire`       |                 | `provider`        | FK vers `Partner`                             |

---

## 10. 💳 PaymentMethod

| Colonne Excel                          | Modèle Django   | Champ Django      | Action                                  |
|---------------------------------------|-----------------|-------------------|-----------------------------------------|
| `N°cheque/Autre_Moyent_de_payement`   | `PaymentMethod` | `payment_number`  | Créer                                   |
| `Date de règlement`                   |                 | `emission_date`   | Convertir au format datetime            |
| `Nom du partenaire`                   |                 | `provider`        | FK vers `Partner`                       |

---

## 11. 👤 Operator

| Colonne Excel         | Modèle Django   | Champ Django   | Action              |
|----------------------|-----------------|----------------|---------------------|
| `Modifié par`        | `Operator`      | `name`         | Créer si inexistant |

---

## 12. 🧾 Claim

| Colonne Excel              | Modèle Django   | Champ Django      | Action                                        |
|---------------------------|-----------------|-------------------|-----------------------------------------------|
| `Numero de sinistre`      | `Claim`         | `id`              | Utiliser comme ID si possible                 |
| `Statut`                  |                 | `status`          | Enum: A, R, C                                 |
| `Date de sinistre`        |                 | `claim_date`      | DateTime                                      |
| `Date de règlement`       |                 | `settlement_date` | DateTime                                      |
| `Nom bénéficiaire`        |                 | `insured`         | FK vers `Insured`                             |
| `Numero de Facture`       |                 | `invoice`         | FK vers `Invoice`                             |
| `Nom Acte`                |                 | `act`             | FK vers `Act`                                 |
| `Modifié par`             |                 | `operator`        | FK vers `Operator`                            |
| `Nom du partenaire`       |                 | `partner`         | FK vers `Partner`                             |
| `Numero de police`        |                 | `policy`          | FK vers `Policy`                              |

---

## 13. 📝 Remarques Globales

- Tous les modèles liés doivent avoir un champ `file` référencé au fichier importé.
- Les noms/textes doivent être nettoyés (`strip()`, `title()`, etc.) avant traitement.
- Les doublons doivent être détectés par `(nom, pays)` ou `(nom, police)` selon le modèle.
- Le champ `country` doit être assigné depuis l’utilisateur si absent dans Excel.
- Tous les enregistrements créés doivent être **liés au fichier `File`** importé.

---

✅ Ce document peut être utilisé comme référence pour le développement, la revue qualité ou la documentation technique du projet d'importation de données santé.

