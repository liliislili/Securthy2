package report

import (
	"fmt"
	"os"
	"strings"
	"time"

	"go-scanner/internal/crypto"
)

type FindingSummary struct {
	IP          string
	Grade       string
	TotalScore  int
	OpenPorts   []string
	Criticals   []string
	Highs       []string
	SMB         string
	RDP         string
	SNMP        string
	Fingerprint string
}

type EmployeeSummary struct {
	Name      string
	Role      string
	Risk      float64
	Grade     string
	Phishing  float64
	Password  float64
	WiFi      float64
	Email     float64
	Privilege float64
}

type TXTReportData struct {
	Target          string
	ScanDate        string
	NetworkHosts    []FindingSummary
	Employees       []EmployeeSummary
	ISOScore        int
	ISOGrade        string
	EmployeeAvgRisk float64
	CombinedScore   int
	CombinedGrade   string
	PackTier        string
	TotalCriticals  int
	TotalHighs      int
}

// GenerateTXT generates:
// 1. A teaser .txt (shown to technician on-site — limited info to drive platform signup)
// 2. An encrypted .sec (full report, readable only by platform)
func GenerateTXT(data TXTReportData, outputPath string) error {
	// Write teaser TXT
	teaser := buildTeaser(data)
	if err := os.WriteFile(outputPath, []byte(teaser), 0644); err != nil {
		return err
	}

	// Write encrypted full report
	full := buildFullReport(data)
	secPath := strings.TrimSuffix(outputPath, ".txt") + ".sec"
	encrypted, err := crypto.EncryptReport([]byte(full))
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}
	if err := os.WriteFile(secPath, encrypted, 0644); err != nil {
		return err
	}

	return nil
}

// buildTeaser — limited info shown to technician on-site
// Enough to show it's serious, not enough to fix without the platform
func buildTeaser(data TXTReportData) string {
	var sb strings.Builder

	line   := func(s string) { sb.WriteString(s + "\n") }
	blank  := func()         { sb.WriteString("\n") }
	bigSep := func()         { line(strings.Repeat("=", 64)) }
	sep    := func()         { line(strings.Repeat("-", 64)) }

	bigSep()
	line("  SECURTHY -- RAPPORT DE SECURITE RESEAU")
	line("  Healthcare Network Security Assessment")
	bigSep()
	blank()
	line(fmt.Sprintf("  Etablissement : %s", data.Target))
	line(fmt.Sprintf("  Date du scan  : %s", data.ScanDate))
	line("  Genere par    : Securthy Platform v1.0")
	blank()

	// ── Score summary ─────────────────────────────────────────────────────────
	bigSep()
	line("  RESUME EXECUTIF -- CONFIDENTIEL")
	bigSep()
	blank()

	// Show ISO score and grade
	line(fmt.Sprintf("  Score ISO 27001  : %d / 100  --  %s",
		data.ISOScore, data.ISOGrade))
	if data.EmployeeAvgRisk > 0 {
		line(fmt.Sprintf("  Risque employes  : %.0f / 100", data.EmployeeAvgRisk))
	}
	line(fmt.Sprintf("  Score combine    : %d / 100  --  %s",
		data.CombinedScore, data.CombinedGrade))
	blank()
	line(fmt.Sprintf("  Vulnerabilites   : %d CRITIQUES  |  %d ELEVEES",
		data.TotalCriticals, data.TotalHighs))
	line(fmt.Sprintf("  Hotes analyses   : %d appareils",
		len(data.NetworkHosts)))
	if len(data.Employees) > 0 {
		line(fmt.Sprintf("  Employes scanes  : %d personnes", len(data.Employees)))
	}
	blank()

	// Show urgency message based on score
	switch {
	case data.CombinedScore < 35:
		line("  [!!!] ETAT CRITIQUE")
		line("        Ce reseau est activement vulnerable aux ransomwares,")
		line("        au vol de donnees patients et aux acces non autorises.")
		line("        Une action immediate est requise.")
	case data.CombinedScore < 60:
		line("  [!] RISQUE ELEVE")
		line("      Des vulnerabilites significatives ont ete detectees.")
		line("      La conformite ISO 27001 est incomplete.")
		line("      Des correctifs sont necessaires sous 30 jours.")
	case data.CombinedScore < 80:
		line("  [i] RISQUE MODERE")
		line("      La posture de securite necessite des ameliorations")
		line("      pour atteindre la conformite ISO 27001.")
	default:
		line("  [OK] POSTURE CORRECTE")
		line("       Les principaux controles ISO 27001 sont respectes.")
	}
	blank()

	// ── Show first 3 criticals only ───────────────────────────────────────────
	sep()
	line("  EXEMPLES DE VULNERABILITES DETECTEES")
	sep()
	blank()

	// Collect all criticals across hosts
	var allCriticals []string
	var allHighs []string
	for _, host := range data.NetworkHosts {
		for _, c := range host.Criticals {
			allCriticals = append(allCriticals, fmt.Sprintf("[%s] %s", host.IP, c))
		}
		for _, h := range host.Highs {
			allHighs = append(allHighs, fmt.Sprintf("[%s] %s", host.IP, h))
		}
	}

	// Show max 3 criticals
	shown := 0
	for _, c := range allCriticals {
		if shown >= 3 {
			break
		}
		line(fmt.Sprintf("  [!!!] %s", truncate(c, 60)))
		shown++
	}

	// Show max 2 highs
	shown = 0
	for _, h := range allHighs {
		if shown >= 2 {
			break
		}
		line(fmt.Sprintf("  [!]   %s", truncate(h, 60)))
		shown++
	}

	// How many more are hidden
	totalShown := 3 + 2
	totalFindings := data.TotalCriticals + data.TotalHighs
	if totalFindings > totalShown {
		blank()
		line(fmt.Sprintf("  ... et %d autres vulnerabilites non affichees.",
			totalFindings-totalShown))
	}
	blank()

	// ── Employee teaser ───────────────────────────────────────────────────────
	if len(data.Employees) > 0 {
		sep()
		line("  APERCU -- RISQUE EMPLOYES")
		sep()
		blank()

		// Show max 2 employees
		for i, emp := range data.Employees {
			if i >= 2 {
				break
			}
			line(fmt.Sprintf("  %s (%s) -- Risque: %.0f/100 -- %s",
				emp.Name, emp.Role, emp.Risk, emp.Grade))
		}
		if len(data.Employees) > 2 {
			line(fmt.Sprintf("  ... et %d autres employes non affiches.",
				len(data.Employees)-2))
		}
		blank()
	}

	// ── Pack recommendation ───────────────────────────────────────────────────
	sep()
	line("  PACK RECOMMANDE : " + strings.ToUpper(data.PackTier))
	sep()
	blank()

	switch {
	case strings.Contains(strings.ToLower(data.PackTier), "essentiel"):
		line("  Pack Essentiel  --  150 000 - 250 000 DZD  --  3-5 jours")
		line("  Correctifs immediats des vulnerabilites les plus critiques.")
		line(fmt.Sprintf("  Score attendu apres pack : %d -> %d / 100",
			data.ISOScore, clamp(data.ISOScore+27)))
	case strings.Contains(strings.ToLower(data.PackTier), "securite"):
		line("  Pack Securite  --  400 000 - 600 000 DZD  --  3-4 semaines")
		line("  Architecture securisee complete avec segmentation VLAN.")
		line(fmt.Sprintf("  Score attendu apres pack : %d -> %d / 100",
			data.ISOScore, clamp(data.ISOScore+50)))
	default:
		line("  Pack Conformite  --  1 000 000 - 1 500 000 DZD  --  2-3 mois")
		line("  Conformite ISO 27001 complete avec rapport Ministere de la Sante.")
		line(fmt.Sprintf("  Score attendu apres pack : %d -> %d / 100",
			data.ISOScore, clamp(data.ISOScore+67)))
	}
	blank()

	// ── Platform CTA ──────────────────────────────────────────────────────────
	bigSep()
	line("  RAPPORT COMPLET DISPONIBLE SUR VOTRE TABLEAU DE BORD")
	bigSep()
	blank()
	line("  Le rapport detaille contient :")
	line("    - La liste complete de toutes les vulnerabilites")
	line("    - Le plan de remediation par appareil")
	line("    - Le detail ISO 27001 par domaine de controle")
	line("    - Les CVEs identifies et leur niveau de risque")
	line("    - Le rapport employes complet")
	blank()
	line("  Acces via votre espace securise :")
	line("  https://app.securthy.dz")
	blank()
	line("  Ce document est un apercu. Le rapport complet est chiffre")
	line("  et accessible uniquement via la plateforme Securthy.")
	blank()
	bigSep()
	line("  Document confidentiel -- Ne pas distribuer")
	line("  Securthy -- Healthcare Security Platform")
	line(fmt.Sprintf("  Genere le %s", time.Now().Format("02 January 2006 15:04")))
	bigSep()

	return sb.String()
}

// buildFullReport — complete report, goes into .sec encrypted file
func buildFullReport(data TXTReportData) string {
	var sb strings.Builder

	line   := func(s string) { sb.WriteString(s + "\n") }
	blank  := func()         { sb.WriteString("\n") }
	sep    := func()         { line(strings.Repeat("-", 64)) }
	bigSep := func()         { line(strings.Repeat("=", 64)) }

	bigSep()
	line("  SECURTHY -- RAPPORT DE SECURITE RESEAU (COMPLET)")
	line("  Healthcare Network Security Assessment")
	bigSep()
	blank()
	line(fmt.Sprintf("  Cible scannee  : %s", data.Target))
	line(fmt.Sprintf("  Date du scan   : %s", data.ScanDate))
	line("  Genere par     : Securthy Platform v1.0")
	blank()

	sep()
	line("  RESUME EXECUTIF")
	sep()
	blank()
	line(fmt.Sprintf("  Score ISO 27001 reseau   : %d / 100  --  %s",
		data.ISOScore, data.ISOGrade))
	if data.EmployeeAvgRisk > 0 {
		line(fmt.Sprintf("  Risque employes moyen    : %.0f / 100", data.EmployeeAvgRisk))
	}
	line(fmt.Sprintf("  Score combine            : %d / 100  --  %s",
		data.CombinedScore, data.CombinedGrade))
	line(fmt.Sprintf("  Pack recommande          : %s", strings.ToUpper(data.PackTier)))
	blank()
	line(fmt.Sprintf("  Vulnerabilites CRITIQUES : %d", data.TotalCriticals))
	line(fmt.Sprintf("  Vulnerabilites ELEVEES   : %d", data.TotalHighs))
	line(fmt.Sprintf("  Hotes analyses           : %d", len(data.NetworkHosts)))
	blank()

	// Full network findings
	if len(data.NetworkHosts) > 0 {
		sep()
		line("  RESULTATS COMPLETS PAR HOTE")
		sep()
		blank()
		for _, host := range data.NetworkHosts {
			line(fmt.Sprintf("  +-- Hote : %s", host.IP))
			line(fmt.Sprintf("  |   Score : %d  |  Grade : %s", host.TotalScore, host.Grade))
			if host.Fingerprint != "" && strings.TrimSpace(host.Fingerprint) != "" {
				line(fmt.Sprintf("  |   Appareil : %s", host.Fingerprint))
			}
			if len(host.OpenPorts) > 0 {
				line(fmt.Sprintf("  |   Ports : %s", strings.Join(host.OpenPorts, ", ")))
			}
			if host.SMB != "" {
				line(fmt.Sprintf("  |   SMB  : %s", host.SMB))
			}
			if host.RDP != "" {
				line(fmt.Sprintf("  |   RDP  : %s", host.RDP))
			}
			if host.SNMP != "" {
				line(fmt.Sprintf("  |   SNMP : %s", host.SNMP))
			}
			if len(host.Criticals) > 0 {
				line("  |")
				line("  |   [!!!] CRITIQUE :")
				for _, c := range host.Criticals {
					line(fmt.Sprintf("  |     - %s", c))
				}
			}
			if len(host.Highs) > 0 {
				line("  |")
				line("  |   [!] ELEVE :")
				for _, h := range host.Highs {
					line(fmt.Sprintf("  |     - %s", h))
				}
			}
			line("  +" + strings.Repeat("-", 54))
			blank()
		}
	}

	// Full employee findings
	if len(data.Employees) > 0 {
		sep()
		line("  RESULTATS COMPLETS PAR EMPLOYE")
		sep()
		blank()
		for _, emp := range data.Employees {
			line(fmt.Sprintf("  +-- %s  (%s)", emp.Name, emp.Role))
			line(fmt.Sprintf("  |   Risque : %.0f/100  --  %s", emp.Risk, emp.Grade))
			line(fmt.Sprintf("  |   Phishing:%.0f  MdP:%.0f  WiFi:%.0f  Email:%.0f  Priv:%.0f",
				emp.Phishing, emp.Password, emp.WiFi, emp.Email, emp.Privilege))
			line("  +" + strings.Repeat("-", 54))
			blank()
		}
	}

	// ISO controls
	sep()
	line("  CONTROLES ISO 27001 EVALUES")
	sep()
	blank()
	line("  A.9  -- Controle d'acces        : credentials, FHIR, RDP NLA, SNMP")
	line("  A.10 -- Cryptographie            : TLS sur DICOM/HL7, certificats")
	line("  A.12 -- Securite operationnelle  : SMBv1, OS obsoletes, Modbus")
	line("  A.13 -- Securite reseau          : VLAN, SMB signing, Telnet, DB")
	line("  A.14 -- Acquisition systemes     : FHIR sans auth, DICOM sans TLS")
	blank()
	line(fmt.Sprintf("  Score global : %d/100  --  %s", data.ISOScore, data.ISOGrade))
	blank()

	// Pack recommendation full detail
	sep()
	line("  PACK RECOMMANDE -- " + strings.ToUpper(data.PackTier))
	sep()
	blank()

	switch {
	case strings.Contains(strings.ToLower(data.PackTier), "essentiel"):
		line("  Pack Essentiel  (150 000 - 250 000 DZD  |  3-5 jours)")
		blank()
		line("  Correctifs inclus :")
		line("    1. Desactivation SMBv1  (vecteur WannaCry / EternalBlue)")
		line("    2. Activation NLA sur RDP  (protection BlueKeep)")
		line("    3. Remplacement credentials par defaut")
		line("    4. Migration Telnet vers SSH")
		line("    5. Regles firewall de base")
		blank()
		line(fmt.Sprintf("  Score attendu : %d -> %d / 100", data.ISOScore, clamp(data.ISOScore+27)))
	case strings.Contains(strings.ToLower(data.PackTier), "securite"):
		line("  Pack Securite  (400 000 - 600 000 DZD  |  3-4 semaines)")
		blank()
		line("  Correctifs inclus :")
		line("    1. Tout le Pack Essentiel")
		line("    2. Segmentation VLAN")
		line("    3. Passerelle TLS pour DICOM")
		line("    4. Tunnel TLS pour HL7/MLLP")
		line("    5. Authentification OAuth2 sur API FHIR DEM")
		line("    6. Signature SMB forcee")
		line("    7. Upgrade SNMPv3")
		blank()
		line(fmt.Sprintf("  Score attendu : %d -> %d / 100", data.ISOScore, clamp(data.ISOScore+50)))
	default:
		line("  Pack Conformite  (1 000 000 - 1 500 000 DZD  |  2-3 mois)")
		blank()
		line("  Correctifs inclus :")
		line("    1. Tout le Pack Securite")
		line("    2. Architecture securite DEM complete")
		line("    3. Plan de reponse aux incidents")
		line("    4. Formation cybersecurite personnel")
		line("    5. Rapport officiel Ministere de la Sante")
		line("    6. Contrat SLA 12 mois + 4 scans trimestriels")
		blank()
		line(fmt.Sprintf("  Score attendu : %d -> %d / 100", data.ISOScore, clamp(data.ISOScore+67)))
	}
	blank()

	bigSep()
	line("  Document confidentiel -- usage interne uniquement")
	line("  Securthy -- Healthcare Security Platform")
	line(fmt.Sprintf("  Genere le %s", time.Now().Format("02 January 2006 15:04")))
	bigSep()

	return sb.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func clamp(n int) int {
	if n > 100 {
		return 100
	}
	return n
}
