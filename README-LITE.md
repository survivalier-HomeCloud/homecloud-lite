# ☁ Home Cloud — édition lite (Termux, sans root)

Version allégée de `homecloud-server` pour un téléphone Android sous **Termux non rooté**.
Même API et même détection réseau que la version complète : **le client Qt fonctionne sans modification**.

## Installation

```sh
unzip homecloud-lite.zip && cd homecloud-lite
sh termux-install.sh
```

Le script installe `clang`, `make` et `openssl`, compile, installe `homecloud-server`, puis lance l'assistant (mode automatique ou manuel, comme sur la version complète).

## Commandes

| Commande | Rôle |
|----------|------|
| `homecloud-server install` | assistant de configuration |
| `homecloud-server start` / `stop` / `restart` | démon en arrière-plan (pose un *wake lock* si `termux-wake-lock` existe) |
| `homecloud-server run` | premier plan, journal à l'écran |
| `homecloud-server status` | état, adresses IP, disques et occupation |
| `homecloud-server passwd <utilisateur>` | réinitialiser un mot de passe (puis `restart`) |

Fichiers : `~/.homecloud/` (config, mots de passe hachés, verrous, avatars, `homecloud.log`, `homecloud.pid`). Variable `HC_HOME` pour changer ce dossier. Données par défaut dans `~/.homecloud/data`.

## Ce qui change par rapport à la version complète

| | Complète | Lite |
|---|---|---|
| Droits | root | **aucun** |
| Disques | `.img` LUKS2 + ext4, montés | **simples dossiers** |
| Taille d'un disque | taille réelle du `.img` | **quota logiciel** (envoi refusé s'il le dépasse, erreur 507) |
| Chiffrement des fichiers | LUKS2 / AES-XTS | **aucun** (voir ci-dessous) |
| Démarrage | systemd | `start`/`stop`, ou **Termux:Boot** |
| Connexions simultanées | 128 | 32 |

Inchangé : comptes et permissions par disque, espace personnel par utilisateur, verrous de fichiers par mot de passe (PBKDF2), sessions de 12 h, API, découverte UDP 8651.

Les métadonnées sensibles (mots de passe, verrous) restent **toujours** dans le dossier privé de Termux, même si vous placez les fichiers sur le stockage partagé (`~/storage/shared`, après `termux-setup-storage`).

## Sécurité

- **Pas de TLS** : à utiliser sur votre Wi-Fi, ou derrière un VPN (WireGuard, Tailscale).
- **Pas de chiffrement des disques** : sans root, impossible de monter LUKS. Les fichiers dans le dossier privé de Termux sont protégés par Android (isolation des applis + chiffrement du téléphone), pas sur le stockage partagé, lisible par les autres applis autorisées.
- Les quotas sont une limite, pas une réservation d'espace. Ils sont vérifiés à l'envoi : deux envois simultanés peuvent dépasser légèrement.

## Android : éviter que le serveur soit coupé

1. Réglages → Batterie → Termux → **Sans restriction** (pas d'optimisation).
2. Gardez la notification Termux (le *wake lock* garde le CPU éveillé).
3. Android 12+ peut tuer les processus d'arrière-plan de Termux : Options pour les développeurs → **« Désactiver les restrictions des processus enfants »** (Android 14+), ou en ADB : `settings put global settings_enable_monitor_phantom_procs false`.
4. Démarrage automatique : installez **Termux:Boot** et acceptez le script proposé par l'assistant (`~/.termux/boot/homecloud-server`).

## Réseau

Ouvrez le client sur le même Wi-Fi : le serveur est détecté (UDP 8651). Si la détection échoue (hotspot, Wi-Fi invité…), saisissez `IP:8650` ; l'IP s'affiche avec `homecloud-server status`.
