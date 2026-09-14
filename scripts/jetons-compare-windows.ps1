# Qu'est-ce qui DIFFERE entre le jeton que notre filtre bloque et celui qu'il
# ne bloque pas ?
#
# A lancer sur essai-windows, en administrateur, shell cmd, depuis la racine du
# banc (le repertoire qui contient les binaires) ou avec BIFROST_BANC pose:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\jetons-compare-windows.ps1
#
# CONTEXTE. La couche 2 pose des filtres WFP de blocage portant une condition
# FWPM_CONDITION_ALE_USER_ID. Cette condition n'est pas un FWP_SID: c'est un
# FWP_SECURITY_DESCRIPTOR_TYPE. WFP fait donc un CONTROLE D'ACCES du jeton du
# processus contre un descripteur de la forme D:(A;;0x1;;;<SID>), ou 0x1 est
# FWP_ACTRL_MATCH_FILTER (cf. crates/bifrost-firewall/src/windows/ffi.rs,
# fonction matching_sddl).
#
# Deux mesures deja faites, avec exactement la meme forme de filtre:
#   - sur un service de test qu'on fabrique: le blocage MORD (0 autorisee,
#     569 refusees, l'evenement 5157 nommant notre filtre);
#   - sur DiagTrack: le blocage ne mord pas, et le 5156 nomme un filtre
#     d'autorisation qui n'est pas a nous.
#
# Chez WFP un blocage bat une autorisation. Si une autorisation gagne, c'est que
# notre filtre n'a PAS MATCHE: le controle d'acces echoue. Or le SID de service
# de DiagTrack EST dans les groupes de son jeton. La sonde precedente a enumere
# les SID mais PAS LEURS ATTRIBUTS: un groupe present mais non active, ou marque
# SE_GROUP_USE_FOR_DENY_ONLY, n'accorde rien. Et si le jeton est RESTREINT, le
# controle est fait deux fois et n'accorde que si les deux passent.
#
# CE QUE CE SCRIPT FAIT. Il lit et compare deux jetons, attribut par attribut:
# celui de DiagTrack, et celui d'un service de test fabrique par la meme recette
# que scripts/telemetrie-cause-windows.ps1 (sc create, sc sidtype unrestricted,
# binaire = le daemon en --connect-probe). Il supprime son service de test a la
# fin, y compris en sortant sur une erreur.
#
# CE QUE CE SCRIPT NE FAIT PAS. Il ne pose AUCUN filtre WFP, ne touche a aucune
# politique d'audit, et ne modifie aucun service existant. DiagTrack n'est que
# LU (au plus demarre s'il est arrete). C'est une tranche de lecture.

param(
    # La racine du banc: le repertoire du script (via -File), ou BIFROST_BANC si pose.
    [string]$Banc = $(if ($env:BIFROST_BANC) { $env:BIFROST_BANC } else { $PSScriptRoot }),
    # Le daemon, qui sert de binaire au service de test.
    [string]$Binaire = (Join-Path $Banc 'bifrost-daemon.exe'),
    # Meme cible et meme rafale que le banc de cause, pour que le service de
    # test soit le MEME temoin que celui dont on sait que le blocage mord.
    [string]$Cible = '1.1.1.1:443',
    [int]$Rafale = 8000,
    [string]$ServiceTest = 'bifrost-jeton',
    [string]$ServiceFiltre = 'bifrost-jeton-filtre',
    # Le service dont le blocage ne mord pas.
    [string]$ServiceReference = 'DiagTrack'
)

# La racine du banc doit etre connue. Lance autrement que par -File et sans
# BIFROST_BANC, $Banc est vide et les chemins derives seraient faux.
if ([string]::IsNullOrEmpty($Banc)) {
    throw "Banc introuvable: lancer ce script par -File depuis la racine du banc (le repertoire qui contient les binaires), ou poser BIFROST_BANC sur ce repertoire."
}

$ErrorActionPreference = 'Continue'

# --------------------------------------------------------- lecture bas niveau
#
# Tout le travail sur les jetons est fait en C#: marshaller TOKEN_GROUPS a la
# main en PowerShell est une source de fautes silencieuses. La classe rend des
# lignes "CLE|champ|champ", que PowerShell reassemble ensuite. Pas d'objet
# complexe a la frontiere, et les lignes brutes sont citables telles quelles.

$source = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class BifrostJeton
{
    // Droits d'ouverture. OpenProcessToken exige PROCESS_QUERY_INFORMATION;
    // PROCESS_QUERY_LIMITED_INFORMATION ne suffit PAS et n'est pas promu vers
    // le premier. Un processus protege (PPL) n'accorde que le second: si
    // l'ouverture retombe sur LIMITED, le jeton est illisible, et c'est un
    // RESULTAT qu'on imprime avec son code d'erreur, pas un cas a contourner.
    const uint PROCESS_QUERY_INFORMATION = 0x0400;
    const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    const uint TOKEN_DUPLICATE = 0x0002;
    const uint TOKEN_IMPERSONATE = 0x0004;
    const uint TOKEN_QUERY = 0x0008;

    // TOKEN_INFORMATION_CLASS, seulement les classes utilisees ici.
    const int TokenUser = 1;
    const int TokenGroups = 2;
    const int TokenPrivileges = 3;
    const int TokenRestrictedSids = 11;
    const int TokenSandBoxInert = 15;
    const int TokenHasRestrictions = 21;
    const int TokenIntegrityLevel = 25;

    // PROCESSINFOCLASS.
    //
    // Il n'existe PAS de classe "ProcessExtendedBasicInformation": la classe 60
    // est ProcessCommandLineInformation, et l'interroger rend
    // STATUS_INFO_LENGTH_MISMATCH (0xC0000004). La variante etendue s'obtient
    // en interrogeant ProcessBasicInformation (classe 0) avec une longueur
    // egale a sizeof(PROCESS_EXTENDED_BASIC_INFORMATION), le champ Size etant
    // renseigne par l'appelant. Erreur commise au premier passage, corrigee.
    const int ProcessBasicInformation = 0;
    const int ProcessProtectionInformation = 61;

    const uint THREAD_QUERY_INFORMATION = 0x0040;
    const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    const uint SE_PRIVILEGE_ENABLED = 0x0002;

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint acces, bool heriter, uint pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CloseHandle(IntPtr h);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool OpenProcessToken(IntPtr proc, uint acces, out IntPtr jeton);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetTokenInformation(IntPtr jeton, int classe, IntPtr tampon, int taille, out int rendu);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool IsTokenRestricted(IntPtr jeton);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr chaine);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool LookupAccountSidW(string systeme, IntPtr sid, StringBuilder nom, ref int cchNom,
        StringBuilder domaine, ref int cchDomaine, out int usage);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool DuplicateTokenEx(IntPtr existant, uint acces, IntPtr attributs,
        int niveau, int type, out IntPtr nouveau);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision,
        out IntPtr sd, IntPtr taille);

    [StructLayout(LayoutKind.Sequential)]
    public struct GENERIC_MAPPING { public uint Lire, Ecrire, Executer, Tout; }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool AccessCheck(IntPtr sd, IntPtr jetonClient, uint acces,
        ref GENERIC_MAPPING mapping, IntPtr privileges, ref int taillePrivileges,
        out uint accorde, out int statut);

    [DllImport("kernel32.dll")]
    static extern IntPtr LocalFree(IntPtr p);

    [DllImport("ntdll.dll")]
    static extern int NtQueryInformationProcess(IntPtr proc, int classe, IntPtr tampon, int taille, out int rendu);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool LookupPrivilegeNameW(string systeme, ref long luid, StringBuilder nom, ref int cchNom);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenThread(uint acces, bool heriter, uint tid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool OpenThreadToken(IntPtr thread, uint acces, bool ouvrirCommeSoi, out IntPtr jeton);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool LookupPrivilegeValueW(string systeme, string nom, out long luid);

    // TOKEN_PRIVILEGES a une seule entree: DWORD PrivilegeCount, puis
    // LUID_AND_ATTRIBUTES { LUID (2 DWORD); DWORD Attributes }. Alignement 4,
    // d'ou Pack = 4 et 16 octets au total.
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct TOKEN_PRIVILEGES
    {
        public int Compte;
        public uint LuidBas;
        public int LuidHaut;
        public uint Attributs;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool AdjustTokenPrivileges(IntPtr jeton, bool toutDesactiver,
        ref TOKEN_PRIVILEGES nouveau, int taille, IntPtr precedent, IntPtr tailleRendue);

    // SeDebugPrivilege est PRESENT mais DESACTIVE dans un jeton administrateur
    // eleve. Sans lui, OpenProcessToken n'obtient que TOKEN_QUERY sur le jeton
    // d'un processus SYSTEM, et la duplication necessaire au controle d'acces
    // simule est refusee (code 5). On ne l'active que sur NOTRE propre jeton,
    // et cela ne modifie rien sur la machine.
    public static string ActiverDebug()
    {
        IntPtr moi;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out moi))
            return "ECHEC OpenProcessToken sur soi, code " + Marshal.GetLastWin32Error();
        try
        {
            long luid;
            if (!LookupPrivilegeValueW(null, "SeDebugPrivilege", out luid))
                return "ECHEC LookupPrivilegeValue, code " + Marshal.GetLastWin32Error();
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            tp.Compte = 1;
            tp.LuidBas = (uint)(luid & 0xFFFFFFFFL);
            tp.LuidHaut = (int)(luid >> 32);
            tp.Attributs = SE_PRIVILEGE_ENABLED;
            if (!AdjustTokenPrivileges(moi, false, ref tp, Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)), IntPtr.Zero, IntPtr.Zero))
                return "ECHEC AdjustTokenPrivileges, code " + Marshal.GetLastWin32Error();
            // AdjustTokenPrivileges rend TRUE meme quand il n'a rien ajuste:
            // seul GetLastError distingue les deux cas.
            int e = Marshal.GetLastWin32Error();
            if (e == 1300) return "PARTIEL: SeDebugPrivilege absent du jeton (ERROR_NOT_ALL_ASSIGNED)";
            if (e != 0) return "ECHEC apres ajustement, code " + e;
            return "OK SeDebugPrivilege active";
        }
        finally { CloseHandle(moi); }
    }

    // Decode les attributs d'un groupe. C'est le point aveugle de la sonde
    // precedente: elle listait les SID sans leur etat. Un groupe present mais
    // non ENABLED, ou marque USE_FOR_DENY_ONLY, n'accorde rien.
    static string Decoder(uint a)
    {
        List<string> l = new List<string>();
        if ((a & 0x00000001) != 0) l.Add("MANDATORY");
        if ((a & 0x00000002) != 0) l.Add("ENABLED_BY_DEFAULT");
        if ((a & 0x00000004) != 0) l.Add("ENABLED");
        if ((a & 0x00000008) != 0) l.Add("OWNER");
        if ((a & 0x00000010) != 0) l.Add("USE_FOR_DENY_ONLY");
        if ((a & 0x00000020) != 0) l.Add("INTEGRITY");
        if ((a & 0x00000040) != 0) l.Add("INTEGRITY_ENABLED");
        if ((a & 0x20000000) != 0) l.Add("RESOURCE");
        if ((a & 0xC0000000) == 0xC0000000) l.Add("LOGON_ID");
        if (l.Count == 0) l.Add("(aucun)");
        return string.Join("+", l.ToArray());
    }

    static string SidTexte(IntPtr sid)
    {
        IntPtr s;
        if (!ConvertSidToStringSidW(sid, out s)) return "(illisible:" + Marshal.GetLastWin32Error() + ")";
        string r = Marshal.PtrToStringUni(s);
        LocalFree(s);
        return r;
    }

    static string SidNom(IntPtr sid)
    {
        StringBuilder n = new StringBuilder(512);
        StringBuilder d = new StringBuilder(512);
        int cn = 512, cd = 512, usage;
        if (!LookupAccountSidW(null, sid, n, ref cn, d, ref cd, out usage))
            return "(non resolu:" + Marshal.GetLastWin32Error() + ")";
        if (d.Length > 0) return d.ToString() + "\\" + n.ToString();
        return n.ToString();
    }

    // Disposition de TOKEN_GROUPS: DWORD GroupCount, puis un tableau de
    // SID_AND_ATTRIBUTES { PVOID Sid; DWORD Attributes; }. L'alignement du
    // tableau est celui d'un pointeur, d'ou le calcul plutot qu'un 8 en dur.
    static int TailleEntree() { return IntPtr.Size + IntPtr.Size; }
    static int DebutTableau() { return IntPtr.Size; }

    static bool LireClasse(IntPtr jeton, int classe, out IntPtr tampon, out int taille, out int erreur)
    {
        tampon = IntPtr.Zero; taille = 0; erreur = 0;
        int besoin;
        GetTokenInformation(jeton, classe, IntPtr.Zero, 0, out besoin);
        // Pour les classes de taille fixe, l'appel de sondage echoue avec
        // ERROR_BAD_LENGTH sans toujours renseigner ReturnLength: on retombe
        // sur un tampon confortable. Il est mis a zero, faute de quoi une
        // classe qui n'ecrit rien laisse lire du residu de tas et le residu
        // se lit comme une mesure. Vecu: TokenHasRestrictions a rendu
        // -1366605567 puis 5308416, deux valeurs de tas, sur deux jetons
        // pourtant tous deux non restreints.
        if (besoin <= 0) besoin = 64;
        IntPtr b = Marshal.AllocHGlobal(besoin);
        for (int i = 0; i < besoin; i++) Marshal.WriteByte(b, i, 0);
        int rendu;
        if (!GetTokenInformation(jeton, classe, b, besoin, out rendu))
        {
            erreur = Marshal.GetLastWin32Error();
            Marshal.FreeHGlobal(b);
            return false;
        }
        tampon = b; taille = rendu;
        return true;
    }

    static void ListerGroupes(List<string> sortie, string cle, IntPtr jeton, int classe)
    {
        IntPtr b; int taille, err;
        if (!LireClasse(jeton, classe, out b, out taille, out err))
        {
            sortie.Add(cle + "_ECHEC|" + err);
            return;
        }
        try
        {
            int n = Marshal.ReadInt32(b);
            sortie.Add(cle + "_COMPTE|" + n);
            for (int i = 0; i < n; i++)
            {
                IntPtr e = new IntPtr(b.ToInt64() + DebutTableau() + (long)i * TailleEntree());
                IntPtr sid = Marshal.ReadIntPtr(e);
                uint att = (uint)Marshal.ReadInt32(new IntPtr(e.ToInt64() + IntPtr.Size));
                sortie.Add(cle + "|" + i + "|" + SidTexte(sid) + "|" + SidNom(sid)
                    + "|0x" + att.ToString("X8") + "|" + Decoder(att));
            }
        }
        finally { Marshal.FreeHGlobal(b); }
    }

    // TOKEN_PRIVILEGES n'a PAS la disposition de TOKEN_GROUPS: son tableau est
    // fait de LUID_AND_ATTRIBUTES { LUID (2 DWORD); DWORD Attributes }, aligne
    // sur 4, donc 12 octets par entree et un tableau qui commence a 4, sur x64
    // comme sur x86. Reutiliser les offsets des groupes ici donnerait une liste
    // decalee, plausible et fausse.
    static void ListerPrivileges(List<string> sortie, IntPtr jeton)
    {
        IntPtr b; int taille, err;
        if (!LireClasse(jeton, TokenPrivileges, out b, out taille, out err))
        {
            sortie.Add("PRIVILEGE_ECHEC|" + err);
            return;
        }
        try
        {
            int n = Marshal.ReadInt32(b);
            sortie.Add("PRIVILEGE_COMPTE|" + n);
            for (int i = 0; i < n; i++)
            {
                IntPtr e = new IntPtr(b.ToInt64() + 4 + (long)i * 12);
                long luid = Marshal.ReadInt64(e);
                uint att = (uint)Marshal.ReadInt32(new IntPtr(e.ToInt64() + 8));
                StringBuilder nom = new StringBuilder(256);
                int cch = 256;
                string texte = "(non resolu)";
                if (LookupPrivilegeNameW(null, ref luid, nom, ref cch)) texte = nom.ToString();
                List<string> f = new List<string>();
                if ((att & 0x00000001) != 0) f.Add("ENABLED_BY_DEFAULT");
                if ((att & 0x00000002) != 0) f.Add("ENABLED");
                if ((att & 0x00000004) != 0) f.Add("REMOVED");
                if ((att & 0x80000000) != 0) f.Add("USED_FOR_ACCESS");
                if (f.Count == 0) f.Add("(aucun)");
                sortie.Add("PRIVILEGE|" + i + "|" + texte + "|0x" + att.ToString("X8") + "|" + string.Join("+", f.ToArray()));
            }
        }
        finally { Marshal.FreeHGlobal(b); }
    }

    // Simulation du controle d'acces que WFP fait sur ALE_USER_ID.
    //
    // ATTENTION, ce n'est pas une reproduction exacte: l'API utilisateur
    // AccessCheck exige un proprietaire et un groupe dans le descripteur, la
    // ou le SDDL du produit n'en a pas. On en ajoute (O:SY G:SY) pour que
    // l'appel soit legal. Le DACL, lui, est identique au produit. Comme la
    // MEME simulation est appliquee aux deux jetons, la comparaison reste
    // valide meme si le chiffre absolu ne vaut pas pour WFP.
    static void Simuler(List<string> sortie, IntPtr jeton, string sidService)
    {
        if (sidService == null || sidService.Length == 0)
        {
            sortie.Add("ACCESSCHECK|SKIPPED|pas de SID de service dans le jeton");
            return;
        }
        IntPtr imperso = IntPtr.Zero, sd = IntPtr.Zero, priv = IntPtr.Zero;
        try
        {
            // SecurityImpersonation = 2, TokenImpersonation = 2.
            if (!DuplicateTokenEx(jeton, TOKEN_QUERY | TOKEN_IMPERSONATE, IntPtr.Zero, 2, 2, out imperso))
            {
                sortie.Add("ACCESSCHECK|SKIPPED|DuplicateTokenEx refuse, code " + Marshal.GetLastWin32Error());
                return;
            }
            string sddl = "O:SYG:SYD:(A;;0x1;;;" + sidService + ")";
            sortie.Add("ACCESSCHECK_SDDL|" + sddl);
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out sd, IntPtr.Zero))
            {
                sortie.Add("ACCESSCHECK|SKIPPED|SDDL refuse, code " + Marshal.GetLastWin32Error());
                return;
            }
            GENERIC_MAPPING m = new GENERIC_MAPPING();
            priv = Marshal.AllocHGlobal(1024);
            int taillePriv = 1024;
            uint accorde; int statut;
            if (!AccessCheck(sd, imperso, 0x1, ref m, priv, ref taillePriv, out accorde, out statut))
            {
                sortie.Add("ACCESSCHECK|ECHEC_APPEL|" + Marshal.GetLastWin32Error());
                return;
            }
            string verdict = "REFUSE";
            if (statut != 0) verdict = "ACCORDE";
            sortie.Add("ACCESSCHECK|" + verdict + "|masque=0x" + accorde.ToString("X"));
        }
        finally
        {
            if (priv != IntPtr.Zero) Marshal.FreeHGlobal(priv);
            if (sd != IntPtr.Zero) LocalFree(sd);
            if (imperso != IntPtr.Zero) CloseHandle(imperso);
        }
    }

    static void Protection(List<string> sortie, IntPtr proc)
    {
        // ProcessProtectionInformation rend un PS_PROTECTION d'un octet:
        // bits 0-2 = Type (0 aucune, 1 PPL, 2 PP), bit 3 = Audit,
        // bits 4-7 = Signataire. Demande PROCESS_QUERY_LIMITED_INFORMATION.
        IntPtr b = Marshal.AllocHGlobal(8);
        try
        {
            int rendu;
            int st = NtQueryInformationProcess(proc, ProcessProtectionInformation, b, 1, out rendu);
            if (st != 0) sortie.Add("PROTECTION|ECHEC|0x" + st.ToString("X8"));
            else
            {
                byte v = Marshal.ReadByte(b);
                int type = v & 0x07;
                string nomType = "inconnu";
                if (type == 0) nomType = "aucune";
                else if (type == 1) nomType = "ProtectedLight(PPL)";
                else if (type == 2) nomType = "Protected(PP)";
                string audit = "0";
                if ((v & 0x08) != 0) audit = "1";
                sortie.Add("PROTECTION|0x" + v.ToString("X2") + "|" + nomType
                    + "|audit=" + audit + "|signataire=" + ((v >> 4) & 0x0F));
            }
        }
        finally { Marshal.FreeHGlobal(b); }

        // PROCESS_EXTENDED_BASIC_INFORMATION: SIZE_T Size, puis
        // PROCESS_BASIC_INFORMATION, puis un ULONG de drapeaux.
        // Sur x64: 8 + 48 = 56 octets avant les drapeaux, 64 avec l'alignement.
        // La classe interrogee est ProcessBasicInformation: c'est la LONGUEUR
        // passee qui fait basculer le noyau vers la variante etendue.
        int taille = 64;
        int offsetDrapeaux = 56;
        if (IntPtr.Size == 4) { taille = 36; offsetDrapeaux = 28; }
        IntPtr e = Marshal.AllocHGlobal(taille);
        try
        {
            for (int i = 0; i < taille; i++) Marshal.WriteByte(e, i, 0);
            if (IntPtr.Size == 8) Marshal.WriteInt64(e, 0, (long)taille);
            else Marshal.WriteInt32(e, 0, taille);
            int rendu;
            int st = NtQueryInformationProcess(proc, ProcessBasicInformation, e, taille, out rendu);
            if (st != 0) { sortie.Add("EXTBASIC|ECHEC|0x" + st.ToString("X8")); return; }
            uint f = (uint)Marshal.ReadInt32(e, offsetDrapeaux);
            sortie.Add("EXTBASIC|0x" + f.ToString("X8")
                + "|IsProtectedProcess=" + (f & 1)
                + "|IsWow64=" + ((f >> 1) & 1)
                + "|IsProcessDeleting=" + ((f >> 2) & 1)
                + "|IsCrossSessionCreate=" + ((f >> 3) & 1)
                + "|IsFrozen=" + ((f >> 4) & 1)
                + "|IsBackground=" + ((f >> 5) & 1)
                + "|IsStronglyNamed=" + ((f >> 6) & 1)
                + "|IsSecureProcess=" + ((f >> 7) & 1)
                + "|IsSubsystemProcess=" + ((f >> 8) & 1));
        }
        finally { Marshal.FreeHGlobal(e); }
    }

    // Les jetons d'IMPERSONATION portes par les fils du processus.
    //
    // WFP evalue ALE_USER_ID contre le jeton EFFECTIF au moment de la
    // connexion: si le fil qui se connecte usurpe une autre identite, c'est ce
    // jeton-la, et non celui du processus, qui est soumis au controle d'acces.
    // Un fil qui n'usurpe rien rend ERROR_NO_TOKEN (1008), ce qui est le cas
    // normal et non une erreur.
    //
    // C'est un INSTANTANE: une usurpation qui n'existe que le temps d'un appel
    // ne se verra pas ici. Une absence de resultat ne prouve donc rien.
    public static string[] Impersonation(uint[] tids)
    {
        List<string> s = new List<string>();
        int sansJeton = 0;
        int refuses = 0;
        foreach (uint tid in tids)
        {
            IntPtr th = OpenThread(THREAD_QUERY_INFORMATION, false, tid);
            if (th == IntPtr.Zero) { refuses++; continue; }
            try
            {
                IntPtr jt;
                // ouvrirCommeSoi = true: le controle d'acces se fait avec notre
                // contexte, pas avec celui que le fil usurpe.
                if (!OpenThreadToken(th, TOKEN_QUERY, true, out jt))
                {
                    int e = Marshal.GetLastWin32Error();
                    if (e == 1008) sansJeton++;
                    else s.Add("IMPERSO_ECHEC|" + tid + "|" + e);
                    continue;
                }
                try
                {
                    IntPtr b; int t, err;
                    string user = "(illisible)";
                    if (LireClasse(jt, TokenUser, out b, out t, out err))
                    {
                        IntPtr sid = Marshal.ReadIntPtr(b);
                        user = SidTexte(sid) + " " + SidNom(sid);
                        Marshal.FreeHGlobal(b);
                    }
                    s.Add("IMPERSO|" + tid + "|" + user);
                    ListerGroupes(s, "IMPERSO_GROUPE_" + tid, jt, TokenGroups);
                }
                finally { CloseHandle(jt); }
            }
            finally { CloseHandle(th); }
        }
        s.Add("IMPERSO_RESUME|fils=" + tids.Length + "|sans jeton (ERROR_NO_TOKEN)=" + sansJeton
            + "|fils non ouvrables=" + refuses);
        return s.ToArray();
    }

    public static string[] Decrire(uint pid)
    {
        List<string> s = new List<string>();
        s.Add("PID|" + pid);

        IntPtr proc = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
        string mode = "PROCESS_QUERY_INFORMATION";
        if (proc == IntPtr.Zero)
        {
            s.Add("OUVERTURE_PLEINE|ECHEC|" + Marshal.GetLastWin32Error());
            proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            mode = "PROCESS_QUERY_LIMITED_INFORMATION";
            if (proc == IntPtr.Zero)
            {
                s.Add("OUVERTURE|ECHEC|" + Marshal.GetLastWin32Error());
                return s.ToArray();
            }
        }
        s.Add("OUVERTURE|OK|" + mode);

        try
        {
            Protection(s, proc);

            IntPtr jeton;
            bool peutDupliquer = true;
            if (!OpenProcessToken(proc, TOKEN_QUERY | TOKEN_DUPLICATE, out jeton))
            {
                peutDupliquer = false;
                s.Add("JETON_QD|ECHEC|" + Marshal.GetLastWin32Error());
                if (!OpenProcessToken(proc, TOKEN_QUERY, out jeton))
                {
                    s.Add("JETON|ECHEC|" + Marshal.GetLastWin32Error());
                    return s.ToArray();
                }
                s.Add("JETON|OK|TOKEN_QUERY seul, pas de duplication possible");
            }
            else s.Add("JETON|OK|TOKEN_QUERY+TOKEN_DUPLICATE");

            try
            {
                // TokenUser: sous quel compte tourne le processus.
                IntPtr b; int t, err;
                if (LireClasse(jeton, TokenUser, out b, out t, out err))
                {
                    IntPtr sid = Marshal.ReadIntPtr(b);
                    s.Add("USER|" + SidTexte(sid) + "|" + SidNom(sid));
                    Marshal.FreeHGlobal(b);
                }
                else s.Add("USER_ECHEC|" + err);

                // Les groupes, AVEC leurs attributs.
                ListerGroupes(s, "GROUPE", jeton, TokenGroups);

                // Les SID restreignants: s'ils existent, le controle d'acces
                // est fait DEUX fois et doit passer les deux.
                ListerGroupes(s, "RESTREINT", jeton, TokenRestrictedSids);

                // Les privileges. Un jeton FILTRE (cf. TokenHasRestrictions)
                // peut l'avoir ete par suppression de privileges sans qu'aucun
                // groupe ne bouge: c'est le seul endroit ou cela se voit.
                ListerPrivileges(s, jeton);

                if (LireClasse(jeton, TokenSandBoxInert, out b, out t, out err))
                {
                    if (t == 1) s.Add("SANDBOX_INERT|" + Marshal.ReadByte(b) + "|longueur rendue=1");
                    else if (t == 4) s.Add("SANDBOX_INERT|" + Marshal.ReadInt32(b) + "|longueur rendue=4");
                    else s.Add("SANDBOX_INERT|ILLISIBLE|longueur rendue=" + t);
                    Marshal.FreeHGlobal(b);
                }
                else s.Add("SANDBOX_INERT|ECHEC|code " + err);

                string restr = "NON";
                if (IsTokenRestricted(jeton)) restr = "OUI";
                s.Add("IS_TOKEN_RESTRICTED|" + restr);

                // On lit la valeur SELON la longueur rendue, jamais selon la
                // longueur qu'on croit. La documentation annonce un DWORD;
                // Windows 11 25H2 rend 1 octet, un BOOLEAN. Lire 4 octets sur
                // une reponse d'un octet, c'est lire 3 octets de tas et les
                // presenter comme une mesure: c'est ce qu'a fait le premier
                // passage, qui a rendu -1366605567 ici et 5308416 la, soit une
                // difference imaginaire entre deux jetons identiques.
                if (LireClasse(jeton, TokenHasRestrictions, out b, out t, out err))
                {
                    if (t == 1) s.Add("TOKEN_HAS_RESTRICTIONS|" + Marshal.ReadByte(b) + "|longueur rendue=1 (BOOLEAN)");
                    else if (t == 4) s.Add("TOKEN_HAS_RESTRICTIONS|" + Marshal.ReadInt32(b) + "|longueur rendue=4 (DWORD)");
                    else s.Add("TOKEN_HAS_RESTRICTIONS|ILLISIBLE|longueur rendue=" + t + ", ni 1 ni 4");
                    Marshal.FreeHGlobal(b);
                }
                else s.Add("TOKEN_HAS_RESTRICTIONS|ECHEC|code " + err);

                // Niveau d'integrite: TOKEN_MANDATORY_LABEL, meme disposition
                // qu'un SID_AND_ATTRIBUTES.
                if (LireClasse(jeton, TokenIntegrityLevel, out b, out t, out err))
                {
                    IntPtr sid = Marshal.ReadIntPtr(b);
                    uint att = (uint)Marshal.ReadInt32(new IntPtr(b.ToInt64() + IntPtr.Size));
                    s.Add("INTEGRITE|" + SidTexte(sid) + "|" + SidNom(sid) + "|0x" + att.ToString("X8"));
                    Marshal.FreeHGlobal(b);
                }
                else s.Add("INTEGRITE_ECHEC|" + err);

                // Le controle d'acces simule, sur le SID de service du jeton.
                string sidService = "";
                foreach (string ligne in s)
                {
                    if (!ligne.StartsWith("GROUPE|")) continue;
                    string[] p = ligne.Split('|');
                    if (p.Length > 2 && p[2].StartsWith("S-1-5-80-")) { sidService = p[2]; break; }
                }
                if (sidService.Length > 0) s.Add("SID_SERVICE_TROUVE|" + sidService);
                else s.Add("SID_SERVICE_TROUVE|(aucun)");
                // Sans TOKEN_DUPLICATE sur le jeton cible, la simulation ne
                // peut pas avoir lieu: on le DIT, avec le droit qui manque, on
                // ne rend pas un vert par defaut. Observe ici: le DACL du jeton
                // d'un processus SYSTEM n'accorde a BUILTIN\Administrators que
                // la lecture, et SeDebugPrivilege actif n'y change rien - il
                // porte sur le handle de PROCESSUS, pas sur l'objet jeton.
                if (!peutDupliquer)
                    s.Add("ACCESSCHECK|SKIPPED|TOKEN_DUPLICATE refuse sur le jeton cible (code 5), simulation impossible");
                else
                    Simuler(s, jeton, sidService);
            }
            finally { CloseHandle(jeton); }
        }
        finally { CloseHandle(proc); }
        return s.ToArray();
    }
}
'@

if (-not ('BifrostJeton' -as [type])) {
    Add-Type -TypeDefinition $source -Language CSharp
}

# ------------------------------------------------------------------ assemblage

# Reassemble les lignes "CLE|..." en un objet exploitable. On garde le brut:
# c'est lui qu'on cite dans un rapport.
function Assembler($lignes) {
    $o = New-Object psobject
    $o | Add-Member NoteProperty Brut        $lignes
    $o | Add-Member NoteProperty Ouverture   ''
    $o | Add-Member NoteProperty Jeton       ''
    $o | Add-Member NoteProperty User        ''
    $o | Add-Member NoteProperty Groupes     @()
    $o | Add-Member NoteProperty Restreints  @()
    $o | Add-Member NoteProperty Restreint   ''
    $o | Add-Member NoteProperty HasRestr    ''
    $o | Add-Member NoteProperty Integrite   ''
    $o | Add-Member NoteProperty Protection  ''
    $o | Add-Member NoteProperty ExtBasic    ''
    $o | Add-Member NoteProperty SidService  ''
    $o | Add-Member NoteProperty AccessCheck ''
    $o | Add-Member NoteProperty Privileges  @()
    $o | Add-Member NoteProperty Sandbox     ''

    foreach ($l in $lignes) {
        $p = $l -split '\|'
        $reste = ''
        if ($p.Count -gt 1) { $reste = ($p[1..($p.Count - 1)] -join ' ') }
        switch ($p[0]) {
            'OUVERTURE'              { $o.Ouverture = $reste }
            'JETON'                  { $o.Jeton = $reste }
            'USER'                   { $o.User = ($p[1] + '  (' + $p[2] + ')') }
            'IS_TOKEN_RESTRICTED'    { $o.Restreint = $p[1] }
            'TOKEN_HAS_RESTRICTIONS' { $o.HasRestr = $reste }
            'INTEGRITE'              { $o.Integrite = ($p[1] + '  (' + $p[2] + ')  attributs=' + $p[3]) }
            'PROTECTION'             { $o.Protection = $reste }
            'EXTBASIC'               { $o.ExtBasic = $reste }
            'SID_SERVICE_TROUVE'     { $o.SidService = $p[1] }
            'ACCESSCHECK'            { $o.AccessCheck = $reste }
            'SANDBOX_INERT'          { $o.Sandbox = $reste }
            'PRIVILEGE' {
                $q = New-Object psobject
                $q | Add-Member NoteProperty Index $p[1]
                $q | Add-Member NoteProperty Nom   $p[2]
                $q | Add-Member NoteProperty Hex   $p[3]
                $q | Add-Member NoteProperty Flags $p[4]
                $o.Privileges = @($o.Privileges) + @($q)
            }
            'GROUPE' {
                $g = New-Object psobject
                $g | Add-Member NoteProperty Index $p[1]
                $g | Add-Member NoteProperty Sid   $p[2]
                $g | Add-Member NoteProperty Nom   $p[3]
                $g | Add-Member NoteProperty Hex   $p[4]
                $g | Add-Member NoteProperty Flags $p[5]
                $o.Groupes = @($o.Groupes) + @($g)
            }
            'RESTREINT' {
                $g = New-Object psobject
                $g | Add-Member NoteProperty Index $p[1]
                $g | Add-Member NoteProperty Sid   $p[2]
                $g | Add-Member NoteProperty Nom   $p[3]
                $g | Add-Member NoteProperty Hex   $p[4]
                $g | Add-Member NoteProperty Flags $p[5]
                $o.Restreints = @($o.Restreints) + @($g)
            }
        }
    }
    return $o
}

# Le contexte SCM du service.
#
# Le PID se prend par CIM, jamais en analysant "sc queryex": un Select-String
# sur une chaine multiligne rend un seul MatchInfo qui porte tout le texte, ce
# qui a deja produit un PID 103243200000000007864 au lieu de 7864.
#
# Le SERVICE_SID_TYPE se lit dans la base de registre, pas dans la sortie de
# "sc qsidtype": sur une machine en locale francaise la VALEUR est traduite, et
# on ne compare jamais une chaine traduite.
function Contexte($nom) {
    $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$nom'" -ErrorAction SilentlyContinue

    $etat = '(absent)'; $compte = ''; $binpath = ''; $idproc = 0
    if ($svc) {
        $etat = $svc.State
        $compte = $svc.StartName
        $binpath = $svc.PathName
        $idproc = [int]$svc.ProcessId
    }

    # ServiceSidType: 0 = none, 1 = unrestricted, 3 = restricted.
    $sidtype = '(absent de la base de registre, donc 0 = none)'
    $cle = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $nom
    $v = Get-ItemProperty -Path $cle -Name 'ServiceSidType' -ErrorAction SilentlyContinue
    if ($v -ne $null) {
        $n = [int]$v.ServiceSidType
        $etiq = 'valeur inattendue'
        if ($n -eq 0) { $etiq = 'SERVICE_SID_TYPE_NONE' }
        elseif ($n -eq 1) { $etiq = 'SERVICE_SID_TYPE_UNRESTRICTED' }
        elseif ($n -eq 3) { $etiq = 'SERVICE_SID_TYPE_RESTRICTED' }
        $sidtype = "$n ($etiq)"
    }

    # RequiredPrivileges: quand un service en declare, le SCM construit son
    # jeton en FILTRANT celui de LocalSystem pour n'y laisser que ces
    # privileges. C'est la cause candidate d'un TokenHasRestrictions non nul.
    $reqpriv = '(aucune valeur RequiredPrivileges)'
    $reqprivListe = @()
    $w = Get-ItemProperty -Path $cle -Name 'RequiredPrivileges' -ErrorAction SilentlyContinue
    if ($w -ne $null) {
        $reqprivListe = @($w.RequiredPrivileges) | Where-Object { "$_" -ne '' }
        $reqpriv = ($reqprivListe -join ', ')
    }

    # Le SID que le SCM derive du nom. Le SID lui-meme est insensible a la
    # locale, seule l'etiquette autour ne l'est pas: on ne garde que le SID.
    $sid = ''
    $lignes = @(& sc.exe showsid $nom)
    foreach ($l in $lignes) {
        $m = [regex]::Match("$l", 'S-1-5-80(-\d+)+')
        if ($m.Success) { $sid = $m.Value; break }
    }

    $cmd = ''; $parent = ''
    if ($idproc -gt 0) {
        $pr = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$idproc" -ErrorAction SilentlyContinue
        if ($pr) { $cmd = $pr.CommandLine; $parent = $pr.ParentProcessId }
    }

    $c = New-Object psobject
    $c | Add-Member NoteProperty Nom      $nom
    $c | Add-Member NoteProperty Etat     $etat
    $c | Add-Member NoteProperty Compte   $compte
    $c | Add-Member NoteProperty BinPath  $binpath
    $c | Add-Member NoteProperty SidType  $sidtype
    $c | Add-Member NoteProperty ReqPriv  $reqpriv
    $c | Add-Member NoteProperty ReqPrivListe $reqprivListe
    $c | Add-Member NoteProperty SidScm   $sid
    $c | Add-Member NoteProperty Idproc   $idproc
    $c | Add-Member NoteProperty Cmd      $cmd
    $c | Add-Member NoteProperty Parent   $parent
    return $c
}

function Afficher-Contexte($c) {
    Write-Host ("  service      : {0}" -f $c.Nom)
    Write-Host ("  etat         : {0}" -f $c.Etat)
    Write-Host ("  compte SCM   : {0}" -f $c.Compte)
    Write-Host ("  binPath      : {0}" -f $c.BinPath)
    Write-Host ("  ServiceSidType (registre) : {0}" -f $c.SidType)
    Write-Host ("  RequiredPrivileges (reg)  : {0}" -f $c.ReqPriv)
    Write-Host ("  SID derive du nom         : {0}" -f $c.SidScm)
    Write-Host ("  PID (CIM)    : {0}" -f $c.Idproc)
    Write-Host ("  ligne de cde : {0}" -f $c.Cmd)
    Write-Host ("  parent       : {0}" -f $c.Parent)
    # Un svchost peut heberger plusieurs services: le jeton porterait alors
    # plusieurs SID de service, ce qui change la lecture des groupes.
    if ($c.Idproc -gt 0) {
        $colocs = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
            Where-Object { $_.ProcessId -eq $c.Idproc } | Select-Object -ExpandProperty Name)
        Write-Host ("  services partageant ce PID : {0}" -f ($colocs -join ', '))
    }
}

function Afficher-Jeton($etiquette, $o) {
    Write-Host ''
    Write-Host ("--- jeton {0} ---" -f $etiquette)
    Write-Host ("  ouverture             : {0}" -f $o.Ouverture)
    Write-Host ("  jeton                 : {0}" -f $o.Jeton)
    Write-Host ("  protection processus  : {0}" -f $o.Protection)
    Write-Host ("  extbasic              : {0}" -f $o.ExtBasic)
    Write-Host ("  TokenUser             : {0}" -f $o.User)
    Write-Host ("  TokenIntegrityLevel   : {0}" -f $o.Integrite)
    Write-Host ("  IsTokenRestricted     : {0}" -f $o.Restreint)
    Write-Host ("  TokenHasRestrictions  : {0}" -f $o.HasRestr)
    Write-Host ("  TokenRestrictedSids   : {0} entree(s)" -f @($o.Restreints).Count)
    foreach ($g in @($o.Restreints)) {
        Write-Host ("      [{0}] {1}  {2}  {3}" -f $g.Index, $g.Sid, $g.Hex, $g.Flags)
        Write-Host ("           {0}" -f $g.Nom)
    }
    Write-Host ("  TokenGroups           : {0} entree(s)" -f @($o.Groupes).Count)
    foreach ($g in @($o.Groupes)) {
        $marque = ''
        if ($g.Sid -like 'S-1-5-80-*') { $marque = '   <== SID DE SERVICE' }
        Write-Host ("      [{0,2}] {1,-50} {2}  {3}{4}" -f $g.Index, $g.Sid, $g.Hex, $g.Flags, $marque)
        Write-Host ("           {0}" -f $g.Nom)
    }
    Write-Host ("  TokenSandBoxInert     : {0}" -f $o.Sandbox)
    Write-Host ("  TokenPrivileges       : {0} entree(s)" -f @($o.Privileges).Count)
    foreach ($q in @($o.Privileges)) {
        Write-Host ("      [{0,2}] {1,-34} {2}  {3}" -f $q.Index, $q.Nom, $q.Hex, $q.Flags)
    }
    Write-Host ("  SID de service dans le jeton : {0}" -f $o.SidService)
    Write-Host ("  controle d acces simule      : {0}" -f $o.AccessCheck)
}

function Afficher-LigneSidService($etiquette, $o) {
    $g = @(@($o.Groupes) | Where-Object { $_.Sid -like 'S-1-5-80-*' })
    if ($g.Count -eq 0) {
        Write-Host ("  {0,-16} AUCUN SID de service dans les groupes" -f $etiquette)
        return
    }
    foreach ($x in $g) {
        Write-Host ("  {0,-16} {1}" -f $etiquette, $x.Sid)
        Write-Host ("  {0,-16}   attributs {1} = {2}" -f '', $x.Hex, $x.Flags)
        Write-Host ("  {0,-16}   compte    {1}" -f '', $x.Nom)
    }
}

# Instantane des jetons d'usurpation portes par les fils du processus.
# Les identifiants de fil viennent de Get-Process, pas d'une analyse de texte.
function Afficher-Imperso($etiquette, $idproc) {
    Write-Host ''
    Write-Host ("--- usurpation dans les fils de {0} (instantane) ---" -f $etiquette)
    $p = Get-Process -Id $idproc -ErrorAction SilentlyContinue
    if ($p -eq $null) {
        Write-Host ("  SKIPPED  le processus {0} n'existe plus au moment de l'instantane" -f $idproc)
        return
    }
    $tids = @()
    foreach ($t in $p.Threads) { $tids = $tids + [uint32]$t.Id }
    if ($tids.Count -eq 0) { Write-Host '  SKIPPED  aucun fil enumerable'; return }
    foreach ($l in [BifrostJeton]::Impersonation([uint32[]]$tids)) { Write-Host ("  {0}" -f $l) }
}

# Fabrique un service de test, cueille son PID pendant la rafale, lit son jeton
# et rend l'objet assemble. Le service est enregistre pour le menage final.
#
# $privs, s'il est non vide, est pose par "sc privs": le SCM construit alors le
# jeton du service en FILTRANT celui de LocalSystem pour n'y laisser que ces
# privileges. C'est ce qui permet de reproduire, sur un service qu'on maitrise,
# l'etat de jeton observe sur le service de reference.
function Mesurer-Temoin($nom, $privs) {
    # Garde-fou. Ces bancs appellent `sc delete` sur le nom qu'on leur donne, et
    # un nom passe en parametre peut etre celui d'un VRAI service: DiagTrack est
    # deja un parametre de l'un d'eux. On refuse donc tout nom qui ne porte pas
    # le prefixe reserve aux temoins. Ce n'est pas de la paranoia: supprimer un
    # service systeme par une faute de frappe ne se repare pas d'un `sc create`,
    # la configuration d'origine etant perdue.
    if ($nom -notlike 'bifrost-*') {
        Write-Host ("REFUS: {0} ne porte pas le prefixe bifrost-. Ce banc ne fabrique et ne supprime que ses propres temoins." -f $nom)
        throw "nom de service de test refuse: $nom"
    }
    Write-Host ''
    Write-Host ("== temoin fabrique: {0} ==" -f $nom)
    $null = & sc.exe delete $nom    # au cas ou un passage precedent aurait laisse quelque chose
    $null = & sc.exe create $nom binPath= "`"$Binaire`" --connect-probe $Cible --connect-probe-rafale $Rafale" type= own start= demand
    if ($LASTEXITCODE -ne 0) { Write-Host ("ECHEC: creation du service de test {0}" -f $nom); return $null }
    $script:servicesCrees = @($script:servicesCrees) + @($nom)
    $null = & sc.exe sidtype $nom unrestricted
    if (@($privs).Count -gt 0) {
        $arg = (@($privs) -join '/')
        Write-Host ("  sc privs {0} {1}" -f $nom, $arg)
        $null = & sc.exe privs $nom $arg
        if ($LASTEXITCODE -ne 0) { Write-Host ("  ATTENTION: sc privs a rendu {0}, le jeton ne sera pas filtre" -f $LASTEXITCODE) }
    }

    # Le repli par ligne de commande ne discrimine pas DEUX temoins successifs:
    # ils portent le meme binaire et les memes arguments. On releve donc les PID
    # deja presents AVANT de demarrer, et on n'accepte ensuite qu'un PID absent
    # de ce releve. Sans cela, le second temoin se lit sur le processus du
    # premier, encore vivant pour la duree de sa rafale: mesure faite le 22 aout
    # 2026, PID 1836 lu deux fois, et le jeton du second temoin portait le SID
    # de service du premier.
    $avant = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='$NomImage'" -ErrorAction SilentlyContinue |
        Where-Object { "$($_.CommandLine)" -like '*--connect-probe-rafale*' } |
        Select-Object -ExpandProperty ProcessId)
    if (@($avant).Count -gt 0) {
        Write-Host ("  {0} processus temoin deja vivant(s), on attend leur fin: {1}" -f @($avant).Count, ($avant -join ', '))
        for ($w = 0; $w -lt 200; $w++) {
            Start-Sleep -Milliseconds 100
            $encore = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='$NomImage'" -ErrorAction SilentlyContinue |
                Where-Object { "$($_.CommandLine)" -like '*--connect-probe-rafale*' })
            if ($encore.Count -eq 0) { $avant = @(); break }
        }
    }

    # sc start ne rend la main que si le binaire dialogue avec le SCM, ce que
    # --connect-probe ne fait pas: on lance sans bloquer et on cueille le PID au
    # vol pendant la rafale. Une fois le handle ouvert, le jeton reste lisible
    # meme si le processus se termine.
    Start-Process -FilePath 'sc.exe' -ArgumentList 'start', $nom -NoNewWindow
    $ctest = $null
    $idtest = 0
    for ($i = 0; $i -lt 150; $i++) {
        Start-Sleep -Milliseconds 100
        $c = Contexte $nom
        if ($c.Idproc -gt 0) { $ctest = $c; $idtest = $c.Idproc; break }
        # Repli: si le SCM ne publie pas encore le PID, on retrouve le
        # processus par sa ligne de commande, qui porte un marqueur unique.
        # Filtre sur le nom d'image, sinon on enumere tous les processus a
        # chaque tour et la rafale s'acheve avant qu'on ait cueilli le PID.
        $pr = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='$NomImage'" -ErrorAction SilentlyContinue |
            Where-Object { "$($_.CommandLine)" -like '*--connect-probe-rafale*' } |
            Where-Object { $avant -notcontains $_.ProcessId })
        if ($pr.Count -ge 1) { $idtest = [int]$pr[0].ProcessId; $ctest = $c; break }
    }
    if ($idtest -le 0) {
        Write-Host ("SKIPPED  {0} n'a pas expose de PID pendant la rafale de {1} ms." -f $nom, $Rafale)
        Write-Host "         Sans processus vivant il n'y a pas de jeton a lire. Relancer avec -Rafale plus grand."
        return $null
    }
    if ($ctest) { Afficher-Contexte $ctest }
    Write-Host ("  PID retenu pour la lecture : {0}" -f $idtest)
    $o = Assembler ([BifrostJeton]::Decrire([uint32]$idtest))
    # Garde: le jeton lu doit porter le SID que le SCM derive du NOM demande.
    # Un PID cueilli au vol peut appartenir a un autre temoin; une mesure sur le
    # mauvais processus se lit exactement comme une mesure valide.
    $attendu = (Contexte $nom).SidScm
    if ($attendu -ne '' -and $o.SidService -ne $attendu) {
        Write-Host ("  ECHEC DE GARDE: le jeton du PID {0} porte {1}" -f $idtest, $o.SidService)
        Write-Host ("                  or {0} a pour SID {1}. Mauvais processus, mesure jetee." -f $nom, $attendu)
        return $null
    }
    Afficher-Jeton $nom $o
    Afficher-Imperso $nom $idtest
    return $o
}

function Ligne($champ, $a, $b) {
    $verdict = 'DIFFERE'
    if ("$a" -eq "$b") { $verdict = 'identique' }
    Write-Host ("  {0,-24} | {1,-9} | {2}" -f $champ, $verdict, $a)
    Write-Host ("  {0,-24} | {1,-9} | {2}" -f '', '', $b)
}

# ---------------------------------------------------------------------- depart

Write-Host ('=' * 78)
Write-Host 'Comparaison de deux jetons de service'
Write-Host ("hote          : {0}" -f $env:COMPUTERNAME)
Write-Host ("windows       : {0}" -f (Get-CimInstance Win32_OperatingSystem).Version)
Write-Host ("powershell    : {0}" -f $PSVersionTable.PSVersion)
$ident = [Security.Principal.WindowsIdentity]::GetCurrent()
$princ = New-Object Security.Principal.WindowsPrincipal($ident)
Write-Host ("session admin : {0}" -f $princ.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
Write-Host ("SeDebugPrivilege : {0}" -f [BifrostJeton]::ActiverDebug())
Write-Host ('=' * 78)

if (-not (Test-Path $Binaire)) { Write-Host "ECHEC: binaire introuvable: $Binaire"; exit 1 }
$NomImage = Split-Path -Leaf $Binaire

$servicesCrees = @()
$oref = $null
$otest = $null
$ofiltre = $null

try {
    # ---- 1. le service de reference, celui dont le blocage NE MORD PAS
    Write-Host ''
    Write-Host ("== reference: {0} ==" -f $ServiceReference)
    $cref = Contexte $ServiceReference
    if ($cref.Etat -ne 'Running') {
        Write-Host ("  {0} est '{1}', on le demarre pour pouvoir lire son jeton" -f $ServiceReference, $cref.Etat)
        $null = & sc.exe start $ServiceReference
        Start-Sleep -Seconds 3
        $cref = Contexte $ServiceReference
    }
    Afficher-Contexte $cref
    if ($cref.Idproc -le 0) {
        Write-Host ("SKIPPED  {0} n'a pas de PID exploitable (etat {1}): il n'y a pas de jeton a lire." -f $ServiceReference, $cref.Etat)
    } else {
        $oref = Assembler ([BifrostJeton]::Decrire([uint32]$cref.Idproc))
        Afficher-Jeton $ServiceReference $oref
        Afficher-Imperso $ServiceReference $cref.Idproc
    }

    # ---- 2. le service de test, celui dont le blocage MORD
    $otest = Mesurer-Temoin $ServiceTest @()

    # ---- 2 bis. le MEME service, mais avec les RequiredPrivileges de la
    # reference. Si le jeton du temoin bascule alors dans le meme etat que
    # celui de la reference, c'est que la difference relevee est bien celle-la
    # et pas une particularite du service de reference. Une difference qu'on ne
    # sait pas reproduire n'est pas une difference qu'on a comprise.
    $ofiltre = $null
    if (@($cref.ReqPrivListe).Count -gt 0) {
        $ofiltre = Mesurer-Temoin $ServiceFiltre $cref.ReqPrivListe
    } else {
        Write-Host ''
        Write-Host ("SKIPPED  {0} ne declare pas de RequiredPrivileges: rien a reproduire." -f $ServiceReference)
    }

    # ---- 3. la comparaison, qui est la seule chose qu'on cherche
    Write-Host ''
    Write-Host ('=' * 78)
    Write-Host 'TABLEAU COMPARATIF'
    Write-Host ('=' * 78)
    if (($oref -eq $null) -or ($otest -eq $null)) {
        Write-Host 'SKIPPED  un des deux jetons manque, la comparaison ne veut rien dire.'
    } else {
        Write-Host ("  {0,-24} | {1,-9} | 1re ligne = {2}, 2e ligne = {3}" -f 'champ', 'verdict', $ServiceReference, $ServiceTest)
        Write-Host ('  ' + ('-' * 74))
        Ligne 'ouverture'              $oref.Ouverture   $otest.Ouverture
        Ligne 'jeton'                  $oref.Jeton       $otest.Jeton
        Ligne 'protection processus'   $oref.Protection  $otest.Protection
        Ligne 'extbasic'               $oref.ExtBasic    $otest.ExtBasic
        Ligne 'TokenUser'              $oref.User        $otest.User
        Ligne 'TokenIntegrityLevel'    $oref.Integrite   $otest.Integrite
        Ligne 'IsTokenRestricted'      $oref.Restreint   $otest.Restreint
        Ligne 'TokenHasRestrictions'   $oref.HasRestr    $otest.HasRestr
        Ligne 'nb TokenRestrictedSids' @($oref.Restreints).Count @($otest.Restreints).Count
        Ligne 'nb TokenGroups'         @($oref.Groupes).Count    @($otest.Groupes).Count
        Ligne 'SID de service'         $oref.SidService  $otest.SidService
        Ligne 'TokenSandBoxInert'      $oref.Sandbox     $otest.Sandbox
        Ligne 'nb TokenPrivileges'     @($oref.Privileges).Count @($otest.Privileges).Count
        Ligne 'controle d acces'       $oref.AccessCheck $otest.AccessCheck

        # Les privileges presents d'un cote et pas de l'autre: c'est la trace
        # concrete de ce que le filtrage du jeton a retire.
        Write-Host ''
        Write-Host '  --- privileges presents dans un seul des deux jetons ---'
        $pref = @(@($oref.Privileges) | Select-Object -ExpandProperty Nom)
        $ptest = @(@($otest.Privileges) | Select-Object -ExpandProperty Nom)
        $ecartp = 0
        foreach ($q in @($oref.Privileges)) {
            if ($ptest -notcontains $q.Nom) { $ecartp = $ecartp + 1; Write-Host ("  {0,-16} seul: {1} {2}" -f $ServiceReference, $q.Nom, $q.Flags) }
        }
        foreach ($q in @($otest.Privileges)) {
            if ($pref -notcontains $q.Nom) { $ecartp = $ecartp + 1; Write-Host ("  {0,-16} seul: {1} {2}" -f $ServiceTest, $q.Nom, $q.Flags) }
        }
        if ($ecartp -eq 0) { Write-Host '  (aucun)' }

        # La ligne qui porte tout: le SID de service, avec ses attributs.
        Write-Host ''
        Write-Host '  --- la ligne du SID de service, dans chaque jeton ---'
        Afficher-LigneSidService $ServiceReference $oref
        Afficher-LigneSidService $ServiceTest $otest

        # Diff des groupes par SID, pour ne rien rater d'autre.
        Write-Host ''
        Write-Host '  --- groupes presents dans un seul des deux jetons ---'
        $sref = @(@($oref.Groupes) | Select-Object -ExpandProperty Sid)
        $stest = @(@($otest.Groupes) | Select-Object -ExpandProperty Sid)
        foreach ($x in @($oref.Groupes)) {
            if ($stest -notcontains $x.Sid) { Write-Host ("  {0,-16} seul: {1} {2} {3}" -f $ServiceReference, $x.Sid, $x.Hex, $x.Flags) }
        }
        foreach ($x in @($otest.Groupes)) {
            if ($sref -notcontains $x.Sid) { Write-Host ("  {0,-16} seul: {1} {2} {3}" -f $ServiceTest, $x.Sid, $x.Hex, $x.Flags) }
        }

        Write-Host ''
        Write-Host '  --- groupes communs dont les ATTRIBUTS different ---'
        $ecart = 0
        foreach ($x in @($oref.Groupes)) {
            $y = @(@($otest.Groupes) | Where-Object { $_.Sid -eq $x.Sid }) | Select-Object -First 1
            if ($y -and ($y.Hex -ne $x.Hex)) {
                $ecart = $ecart + 1
                Write-Host ("  {0}" -f $x.Sid)
                Write-Host ("      {0,-16} {1} {2}" -f $ServiceReference, $x.Hex, $x.Flags)
                Write-Host ("      {0,-16} {1} {2}" -f $ServiceTest, $y.Hex, $y.Flags)
            }
        }
        if ($ecart -eq 0) { Write-Host '  (aucun)' }
    }

    # ---- 3 bis. le temoin filtre, en regard des deux autres
    if ($ofiltre -ne $null) {
        Write-Host ''
        Write-Host ('=' * 78)
        Write-Host 'REPRODUCTION DE LA DIFFERENCE SUR UN SERVICE MAITRISE'
        Write-Host ('=' * 78)
        Write-Host ("  {0,-26} | {1,-12} | {2}" -f 'service', 'HasRestr', 'nb privileges')
        Write-Host ('  ' + ('-' * 74))
        if ($oref -ne $null)  { Write-Host ("  {0,-26} | {1,-12} | {2}" -f $ServiceReference, $oref.HasRestr, @($oref.Privileges).Count) }
        if ($otest -ne $null) { Write-Host ("  {0,-26} | {1,-12} | {2}" -f $ServiceTest, $otest.HasRestr, @($otest.Privileges).Count) }
        Write-Host ("  {0,-26} | {1,-12} | {2}" -f $ServiceFiltre, $ofiltre.HasRestr, @($ofiltre.Privileges).Count)
        Write-Host ''
        Write-Host ("  SID de service du temoin filtre : {0}" -f $ofiltre.SidService)
        Afficher-LigneSidService $ServiceFiltre $ofiltre
    }

    # ---- 4. les lignes brutes, pour pouvoir citer sans reformuler
    Write-Host ''
    Write-Host ('=' * 78)
    Write-Host 'SORTIE BRUTE'
    Write-Host ('=' * 78)
    if ($oref -ne $null) {
        Write-Host ("--- {0} ---" -f $ServiceReference)
        foreach ($l in $oref.Brut) { Write-Host $l }
    }
    if ($otest -ne $null) {
        Write-Host ("--- {0} ---" -f $ServiceTest)
        foreach ($l in $otest.Brut) { Write-Host $l }
    }
    if ($ofiltre -ne $null) {
        Write-Host ("--- {0} ---" -f $ServiceFiltre)
        foreach ($l in $ofiltre.Brut) { Write-Host $l }
    }
}
finally {
    # Menage: on supprime UNIQUEMENT le service qu'on a cree. Aucun service
    # existant n'est touche.
    Write-Host ''
    if (@($servicesCrees).Count -gt 0) {
      foreach ($ServiceAsupprimer in @($servicesCrees)) {
        # Un service dont le binaire ne dialogue pas avec le SCM ne repond pas a
        # sc stop, et sc delete le marque seulement POUR suppression tant que le
        # processus vit. Vecu au premier passage: la verification faite tout de
        # suite a crie au service fuite alors qu'il partait deux secondes plus
        # tard. On attend donc la fin du processus, puis on reverifie en boucle.
        $null = & sc.exe stop $ServiceAsupprimer
        $null = & sc.exe delete $ServiceAsupprimer
        $parti = $false
        for ($k = 0; $k -lt 60; $k++) {
            Start-Sleep -Milliseconds 500
            $reste = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceAsupprimer'" -ErrorAction SilentlyContinue
            $reste2 = Get-Service -Name $ServiceAsupprimer -ErrorAction SilentlyContinue
            if (($reste -eq $null) -and ($reste2 -eq $null)) { $parti = $true; break }
            # Nouvelle tentative periodique, une fois le processus termine.
            if (($k % 6) -eq 5) { $null = & sc.exe delete $ServiceAsupprimer }
        }
        if ($parti) {
            Write-Host ("menage: le service {0} est supprime (Win32_Service et Get-Service ne le trouvent plus)" -f $ServiceAsupprimer)
        } else {
            Write-Host ("ATTENTION: le service {0} est encore present apres 30 s, le supprimer a la main" -f $ServiceAsupprimer)
        }
      }
    } else {
        Write-Host 'menage: aucun service de test n avait ete cree'
    }
    Write-Host 'aucun filtre WFP pose, aucune politique d audit touchee, aucun service existant modifie'
}
