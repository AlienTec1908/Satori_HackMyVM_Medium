# Satori - HackMyVM (Medium)

![Satori.png](Satori.png)

## Übersicht

*   **VM:** Satori
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Satori)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 3. März 2021
*   **Original-Writeup:** https://alientec1908.github.io/Satori_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Satori" zu erlangen. Der Weg dorthin begann mit der Entdeckung eines anonymen FTP-Zugangs, der eine verschlüsselte Datei (`init.py.bak` im UDP-Broadcast, später `darkness.txt` mit Hinweis) enthielt. Nach dem Knacken des Verschlüsselungspassworts (`amoajesus`) wurde ein privater SSH-Schlüssel enthüllt. Mittels Benutzerenumeration via Metasploit wurde der zugehörige Benutzer `abraham` identifiziert, was einen SSH-Login ermöglichte. Die finale Rechteausweitung zu Root gelang durch Ausnutzung der Mitgliedschaft des Benutzers `abraham` in der Gruppe `disk`. Dies erlaubte den direkten Zugriff auf das Blockgerät (`/dev/sda1`) mit `debugfs`, um den privaten SSH-Schlüssel des Root-Benutzers auszulesen.

*Alternativer Pfad im Bericht:* Ein FTP-Brute-Force auf den Benutzer `yana` (dessen Name via LFI auf `stream.php` gefunden wurde) mit dem Passwort `truelove` war ebenfalls erfolgreich und lieferte denselben privaten SSH-Schlüssel für `yana` (der identisch mit dem von `abraham` zu sein scheint oder der Bericht hier die Pfade vermischt). Die LFI auf `stream.php` (Parameter `url`) wurde ebenfalls erwähnt, war aber für den finalen Root-Zugang über `debugfs` nicht der primäre Weg nach dem `abraham`-Login.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `ftp` / `lftp`
*   `mv`
*   `gobuster`
*   `wfuzz`
*   `curl`
*   `php` (lokal für Server)
*   `hydra`
*   `ssh`
*   `nc` (netcat)
*   `base64`
*   `file`
*   `bruteforce-salted-openssl`
*   `openssl`
*   `ssh2john`
*   `msfconsole` (Metasploit Framework)
*   `debugfs`
*   Standard Linux-Befehle (`cat`, `grep`, `nano`, `chmod`, `ls`, `id`, `whereis`, `export`, `df`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Satori" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Enumeration (FTP, Web, SNMP):**
    *   IP-Adresse des Ziels (192.168.2.159 – Abweichung vom ARP-Scan, der .140 für Pickle zeigte, aber Nmap auf .159 für Satori) identifiziert. Hostname `satori.hmv` in `/etc/hosts` eingetragen.
    *   `nmap`-Scan offenbarte Port 21 (FTP, vsftpd 3.0.3, anonymer Login erlaubt), 22 (SSH, OpenSSH 7.9p1) und 80 (HTTP, Nginx 1.14.2).
    *   Auf dem anonymen FTP-Server wurde `darkness.txt` gefunden ("In the darkness, there are invisible things...").
    *   Ein Netcat-Listener auf UDP Port 24000 empfing einen Base64-kodierten, mit OpenSSL verschlüsselten Datenblock (`U2FsdGVkX1+...`).
    *   Der Webserver auf Port 80 enthielt `stream.php`. `wfuzz` fand den Parameter `url`.
    *   Die LFI/SSRF-Schwachstelle in `stream.php?url=` wurde genutzt, um `file:///etc/passwd` zu lesen (Benutzer `yana` identifiziert) und `file:///home/yana/.ssh/id_rsa` (privater SSH-Schlüssel von `yana`).

2.  **Initial Access (SSH als `yana` oder `abraham`):**
    *   **Pfad 1 (UDP Leak zu `abraham`):**
        *   Der Base64-Block vom UDP-Port wurde dekodiert (`base64 -d > out`).
        *   Mittels `bruteforce-salted-openssl` und `rockyou.txt` wurde das Passwort `amoajesus` für die Datei `out` gefunden.
        *   `openssl enc -aes-256-cbc -d -in out -out decrypt_file` entschlüsselte die Datei zu einem privaten SSH-Schlüssel (nicht passwortgeschützt).
        *   Mittels Metasploit (`auxiliary/scanner/ssh/ssh_enumusers`) wurde der Benutzer `abraham` enumeriert.
        *   Erfolgreicher SSH-Login als `abraham` mit dem entschlüsselten Schlüssel.
    *   **Pfad 2 (LFI/FTP zu `yana`):**
        *   Der über LFI exfiltrierte private SSH-Schlüssel von `yana` wurde verwendet.
        *   Alternativ wurde mit `hydra` das FTP-Passwort für `yana` zu `truelove` gebruteforced. Über FTP wurde derselbe private SSH-Schlüssel von `yana` heruntergeladen.
        *   Erfolgreicher SSH-Login als `yana` mit dem Schlüssel.

3.  **Privilege Escalation (von `yana`/`abraham` zu `root` via `debugfs`):**
    *   Als Benutzer `yana` (oder `abraham`) wurde mit `id` oder `groups` die Mitgliedschaft in der Gruppe `disk` festgestellt.
    *   Das Tool `/usr/sbin/debugfs` wurde verwendet, um direkten Zugriff auf das Root-Dateisystem (`/dev/sda1`) zu erhalten: `debugfs /dev/sda1`.
    *   Innerhalb von `debugfs` wurde mit `cat /root/.ssh/id_rsa` der private SSH-Schlüssel des Root-Benutzers ausgelesen.
    *   Der Root-SSH-Schlüssel wurde auf dem Angreifer-System gespeichert (`root_ssh`), die Berechtigungen gesetzt (`chmod 600`).
    *   Erfolgreicher SSH-Login als `root@satori.hmv` mit dem extrahierten Root-Schlüssel.
    *   Die User-Flag (`HMVEnlightment` in `/home/yana/user.txt`) und Root-Flag (`whoteachbudha` in `/root/root.txt`) wurden gefunden.

## Wichtige Schwachstellen und Konzepte

*   **Information Disclosure (UDP Broadcast & FTP):** Ein verschlüsselter privater SSH-Schlüssel wurde über einen UDP-Broadcast gesendet. Eine Hinweisdatei (`darkness.txt`) befand sich auf einem anonymen FTP-Server.
*   **Passwort-Cracking (OpenSSL & FTP):** Das Passwort für die OpenSSL-Verschlüsselung und das FTP-Passwort für `yana` konnten geknackt werden.
*   **Local File Inclusion (LFI) / Server-Side Request Forgery (SSRF):** Das Skript `stream.php` war anfällig und erlaubte das Auslesen lokaler Dateien, einschließlich SSH-Schlüsseln.
*   **Unsichere Gruppenmitgliedschaft (Gruppe `disk`):** Die Mitgliedschaft eines normalen Benutzers in der Gruppe `disk` ermöglichte direkten Lesezugriff auf Blockgeräte und das Umgehen von Dateisystemberechtigungen mittels `debugfs`.
*   **Exponierte private SSH-Schlüssel:** Sowohl für `yana`/`abraham` als auch für `root` konnten private Schlüssel erlangt werden.

## Flags

*   **User Flag (`/home/yana/user.txt`):** `HMVEnlightment`
*   **Root Flag (`/root/root.txt`):** `whoteachbudha`

## Tags

`HackMyVM`, `Satori`, `Medium`, `UDP Leak`, `OpenSSL Encryption Crack`, `LFI`, `SSRF`, `FTP Brute-Force`, `SSH Key Leak`, `debugfs`, `disk group exploit`, `Linux`, `Web`, `Privilege Escalation`, `vsftpd`, `Nginx`
