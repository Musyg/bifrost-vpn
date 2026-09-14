#!/usr/bin/env python3
"""Chronologie d'une conversation QUIC obfusquee, lue dans une capture.

Ecrit pour diagnostiquer une panne Hysteria2 muette, ou aucune des deux
extremites ne disait rien d'utile. Conserve parce que les quatre pieges qu'il
contourne ont chacun coute une fausse conclusion, et qu'aucun ne se voit a la
lecture d'un decodeur naif.

1. `tcpdump -i any` encapsule en Linux SLL, pas en Ethernet. Sans le saut
   d'en-tete correspondant, aucune trame ne commence par de l'IP et le
   decodeur rend zero paquet EN SILENCE, ce qui se lit comme "rien n'est passe
   sur le reseau". `pktmon` cote Windows fait l'inverse: il declare le type
   Ethernet et ecrit de l'IP brute.

2. Un fragment IP non initial ne porte PAS d'en-tete UDP. Un filtre BPF
   `port N` ne peut donc pas le matcher, et exclut par construction exactement
   ce qu'on cherche quand on enquete sur de la fragmentation. Capturer sans
   filtre de port, et filtrer ici.

3. Linux met l'identifiant IP a zero sur les paquets portant DF. Grouper les
   fragments par (source, destination, identifiant) fusionne alors tous les
   datagrammes non fragmentes en un seul. Le decalage est visible a ce que le
   nombre de datagrammes ne correspond plus entre les deux bouts: c'est le
   controle a faire avant de croire une sortie.

4. Le mot de passe Salamander est un secret. Il est lu sur la machine qui le
   detient et n'est jamais affiche: le sortir de la pour decoder une capture
   serait payer un secret contre un diagnostic.

L'obfuscation Salamander est un XOR: `sortie[i] = entree[8+i] ^ cle[i % 32]`,
ou `cle = BLAKE2b-256(mot_de_passe || sel)` et le sel est les 8 premiers
octets du datagramme.

Les bits de type d'un en-tete long QUIC ne sont PAS proteges, ce qui permet de
nommer Initial, 0-RTT, Handshake et Retry sans dechiffrer quoi que ce soit.
C'est tout ce dont on a besoin: l'absence d'un `Initial` porteur du ServerHello
dans le sens serveur vers client suffit a expliquer un client qui reemet sans
fin.

Un contenu annonce a une longueur absurde (superieure au datagramme) signale du
trafic qui n'est pas celui qu'on croit: capturer sur `host X` sans filtre de
port ramasse aussi WireGuard, Tailscale et le reste, que ce decodeur lit alors
comme du QUIC. Filtrer sur le port des que la fragmentation n'est plus en
cause.

Usage:
    quic-chronologie.py <capture.pcap> <ip-du-client> <fichier-mot-de-passe>

Le fichier de mot de passe contient le secret Salamander, sans rien d'autre.
"""

import hashlib
import socket
import struct
import sys

TAILLE_SEL = 8
TYPES = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}
# Octets a sauter avant l'en-tete IP, par type de lien pcap.
SAUT_PAR_LIEN = {101: 0, 1: 14, 113: 16, 276: 20}
PROTO_UDP = 17


def desobfusquer(charge, secret):
    cle = hashlib.blake2b(secret + charge[:TAILLE_SEL], digest_size=32).digest()
    return bytes(o ^ cle[i % 32] for i, o in enumerate(charge[TAILLE_SEL:]))


def varint(b, i):
    """Entier de longueur variable QUIC, RFC 9000 section 16."""
    n = 1 << (b[i] >> 6)
    v = b[i] & 0x3F
    for k in range(1, n):
        v = (v << 8) | b[i + k]
    return v, i + n


def paquets_coalesces(q):
    """Nomme les paquets QUIC d'un datagramme deobfusque.

    Plusieurs paquets peuvent tenir dans un datagramme, par niveau de
    chiffrement croissant. Ne pas les parcourir ferait manquer le ServerHello,
    qui voyage coalesce avec le debut du Handshake.
    """
    trouves, i = [], 0
    while i < len(q):
        if not (q[i] & 0x80):
            trouves.append(f"1-RTT({len(q) - i}o)")
            break
        try:
            t = TYPES.get((q[i] & 0x30) >> 4, "?")
            if struct.unpack("!I", q[i + 1 : i + 5])[0] == 0:
                trouves.append("VersionNego")
                break
            j = i + 5
            j += 1 + q[j]  # identifiant de connexion destination
            j += 1 + q[j]  # identifiant de connexion source
            if t == "Retry":
                trouves.append(f"Retry({len(q) - i}o)")
                break
            if t == "Initial":
                longueur_jeton, j = varint(q, j)
                j += longueur_jeton
            longueur, j = varint(q, j)
            trouves.append(f"{t}({j + longueur - i}o)")
            i = j + longueur
        except (IndexError, struct.error):
            trouves.append(f"illisible({len(q) - i}o)")
            break
    return trouves


def lire(capture, client, secret):
    """Rend la liste des datagrammes, fragments reassembles."""
    f = open(capture, "rb")
    (lien,) = struct.unpack("<I", f.read(24)[20:24])
    saut = SAUT_PAR_LIEN.get(lien, 0)

    en_cours, origine, lignes = {}, None, []
    while True:
        entete = f.read(16)
        if len(entete) < 16:
            break
        s, us, taille_capturee, _ = struct.unpack("<IIII", entete)
        p = f.read(taille_capturee)[saut:]
        if not p or (p[0] >> 4) != 4 or p[9] != PROTO_UDP:
            continue
        t = s + us / 1e6
        if origine is None:
            origine = t

        ihl = (p[0] & 0x0F) * 4
        total = struct.unpack("!H", p[2:4])[0]
        drapeaux = struct.unpack("!H", p[6:8])[0]
        encore, decalage = bool(drapeaux & 0x2000), (drapeaux & 0x1FFF) * 8
        df = bool(drapeaux & 0x4000)
        sens = (
            "client -> serveur"
            if socket.inet_ntoa(p[12:16]) == client
            else "serveur -> client"
        )

        if not encore and decalage == 0:
            udp = p[ihl:]
            fin = struct.unpack("!H", udp[4:6])[0]
            charge = udp[8:fin]
            lignes.append(
                (t - origine, sens, total, df, "entier", paquets_coalesces(
                    desobfusquer(charge, secret)))
            )
            continue

        cle = (p[12:16], p[16:20], struct.unpack("!H", p[4:6])[0])
        e = en_cours.setdefault(cle, {"bouts": {}, "fin": None, "t": t, "df": df})
        e["bouts"][decalage] = p[ihl:]
        if not encore:
            e["fin"] = decalage + total - ihl
        if e["fin"] is not None and sum(len(x) for x in e["bouts"].values()) >= e["fin"]:
            assemble = bytearray(e["fin"])
            for d, bout in e["bouts"].items():
                assemble[d : d + len(bout)] = bout
            fin = struct.unpack("!H", bytes(assemble[4:6]))[0]
            charge = bytes(assemble[8:fin])
            lignes.append(
                (
                    e["t"] - origine,
                    sens,
                    e["fin"] + ihl,
                    e["df"],
                    f"{len(e['bouts'])} fragments",
                    paquets_coalesces(desobfusquer(charge, secret)),
                )
            )
            del en_cours[cle]

    return lignes, en_cours


def main():
    if len(sys.argv) != 4:
        print(
            "usage: quic-chronologie.py <capture.pcap> <ip-du-client> "
            "<fichier-mot-de-passe>",
            file=sys.stderr,
        )
        return 2
    capture, client, fichier_secret = sys.argv[1:4]
    secret = open(fichier_secret, "rb").read().strip()

    lignes, incomplets = lire(capture, client, secret)
    for t, sens, taille, df, etat, paquets in lignes:
        marque = "DF" if df else "  "
        print(f"  t+{t:6.3f}s  {sens}  {taille:5}o {marque}  {etat:<13} "
              f"{', '.join(paquets)}")

    if not lignes:
        print("  AUCUN datagramme UDP decode. Verifier le type de lien de la "
              "capture et l'adresse du client avant de conclure quoi que ce "
              "soit du reseau.")
    for cle, e in incomplets.items():
        print(f"  INCOMPLET: id={cle[2]:#06x}, {len(e['bouts'])} morceau(x), "
              f"attendu {e['fin']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
