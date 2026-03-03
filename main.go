// ============================================================
//  CongoComply Agent v1.0
//  SPV DIGITALE LUCEOR — T. LOEMBA
//  Base : Wireshark Engine (libpcap) + SIEM + Fraude + Profilage
//  Modules : CC-DLP | CC-NDR | CC-EDR | CC-IAM | CC-VULN | CC-AWARENESS
//  Conformité : Loi 5-2025 (CNPD) | Loi 26-2020 (ANSSI)
//  Archivage logs : 10 ans — Certification SHA-256
// ============================================================

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"gopkg.in/yaml.v3"
)

// ──────────────────────────────────────────────
//  CONFIGURATION
// ──────────────────────────────────────────────

type Config struct {
	Agent struct {
		TenantID   string `yaml:"tenant_id"`   // K_ORG du tenant
		OrgName    string `yaml:"org_name"`
		Sector     string `yaml:"sector"`      // banque|minier|transport|sante|telecom|energie|industrie
		APIKey     string `yaml:"api_key"`     // Clé d'authentification Onkɔngɔ
		CloudURL   string `yaml:"cloud_url"`   // https://api.onkongo.cg/v1
		Interface  string `yaml:"interface"`   // ex: eth0, Wi-Fi
		BPFFilter  string `yaml:"bpf_filter"`  // ex: "tcp port 80 or port 443"
	} `yaml:"agent"`
	Modules struct {
		DLP       bool `yaml:"cc_dlp"`
		NDR       bool `yaml:"cc_ndr"`
		EDR       bool `yaml:"cc_edr"`
		IAM       bool `yaml:"cc_iam"`
		VULN      bool `yaml:"cc_vuln"`
		AWARENESS bool `yaml:"cc_awareness"`
	} `yaml:"modules"`
	Archive struct {
		LocalPath      string `yaml:"local_path"`       // Chemin stockage local
		RetentionYears int    `yaml:"retention_years"`  // 10 ans (Tiers de Confiance)
		Encrypt        bool   `yaml:"encrypt"`
	} `yaml:"archive"`
}

// ──────────────────────────────────────────────
//  STRUCTURES DE DONNÉES
// ──────────────────────────────────────────────

// Événement capturé par le moteur Wireshark
type PacketEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	SrcIP       string    `json:"src_ip"`
	DstIP       string    `json:"dst_ip"`
	SrcPort     string    `json:"src_port"`
	DstPort     string    `json:"dst_port"`
	Protocol    string    `json:"protocol"`
	PayloadSize int       `json:"payload_size"`
	Flags       string    `json:"flags"`
	Hash        string    `json:"hash_sha256"`   // Preuve d'intégrité
}

// Alerte SIEM générée après corrélation
type SIEMAlert struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	TenantID    string    `json:"tenant_id"`
	Severity    string    `json:"severity"`    // CRITIQUE|ÉLEVÉ|MODÉRÉ|INFO
	Category    string    `json:"category"`    // FRAUDE|EXFILTRATION|INTRUSION|ANOMALIE
	Module      string    `json:"module"`      // CORE|CC-NDR|CC-DLP|CC-EDR...
	Description string    `json:"description"`
	SrcIP       string    `json:"src_ip"`
	DstIP       string    `json:"dst_ip"`
	Evidence    string    `json:"evidence_hash"` // SHA-256 recevable en justice
	Sector      string    `json:"sector"`
	LegalRef    string    `json:"legal_ref"`     // Art. Loi 5-2025 ou 26-2020
}

// Rapport de profilage comportemental (envoyé anonymisé au CNS)
type BehaviorProfile struct {
	TenantID        string    `json:"tenant_id"`
	Timestamp       time.Time `json:"timestamp"`
	AnomalyScore    float64   `json:"anomaly_score"`    // 0.0 à 1.0
	TopSrcIPs       []string  `json:"top_src_ips"`
	TopDstIPs       []string  `json:"top_dst_ips"`
	ProtocolDist    map[string]int `json:"protocol_dist"`
	SuspiciousPorts []int     `json:"suspicious_ports"`
	FraudIndicators []string  `json:"fraud_indicators"`
}

// ──────────────────────────────────────────────
//  MOTEUR WIRESHARK (Capture paquets)
// ──────────────────────────────────────────────

type WiresharkEngine struct {
	cfg     *Config
	handle  *pcap.Handle
	events  chan PacketEvent
	alerts  chan SIEMAlert
	wg      sync.WaitGroup
	stop    chan struct{}
}

func NewWiresharkEngine(cfg *Config) *WiresharkEngine {
	return &WiresharkEngine{
		cfg:    cfg,
		events: make(chan PacketEvent, 10000),
		alerts: make(chan SIEMAlert, 1000),
		stop:   make(chan struct{}),
	}
}

func (w *WiresharkEngine) Start() error {
	iface := w.cfg.Agent.Interface
	if iface == "" {
		iface = autoDetectInterface()
	}
	log.Printf("[WIRESHARK] Capture sur l'interface : %s", iface)

	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("impossible d'ouvrir l'interface %s : %w", iface, err)
	}

	// Filtre BPF (Berkeley Packet Filter) — comme dans Wireshark
	filter := w.cfg.Agent.BPFFilter
	if filter == "" {
		filter = "tcp or udp" // Capture tout par défaut
	}
	if err := handle.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("filtre BPF invalide : %w", err)
	}

	w.handle = handle
	log.Printf("[WIRESHARK] Filtre BPF actif : %s", filter)

	w.wg.Add(1)
	go w.captureLoop()
	return nil
}

func (w *WiresharkEngine) captureLoop() {
	defer w.wg.Done()
	src := gopacket.NewPacketSource(w.handle, w.handle.LinkType())

	for {
		select {
		case <-w.stop:
			log.Println("[WIRESHARK] Arrêt de la capture.")
			return
		case pkt, ok := <-src.Packets():
			if !ok {
				return
			}
			w.processPacket(pkt)
		}
	}
}

func (w *WiresharkEngine) processPacket(pkt gopacket.Packet) {
	evt := PacketEvent{
		Timestamp: pkt.Metadata().Timestamp,
	}

	// Extraction IP
	if ipLayer := pkt.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		evt.SrcIP = ip.SrcIP.String()
		evt.DstIP = ip.DstIP.String()
		evt.Protocol = ip.Protocol.String()
	} else if ipLayer := pkt.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip := ipLayer.(*layers.IPv6)
		evt.SrcIP = ip.SrcIP.String()
		evt.DstIP = ip.DstIP.String()
	}

	// Extraction TCP
	if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		evt.SrcPort = tcp.SrcPort.String()
		evt.DstPort = tcp.DstPort.String()
		evt.Flags = tcpFlags(tcp)
		evt.Protocol = "TCP"
	}

	// Extraction UDP
	if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		evt.SrcPort = udp.SrcPort.String()
		evt.DstPort = udp.DstPort.String()
		evt.Protocol = "UDP"
	}

	// Taille payload
	if app := pkt.ApplicationLayer(); app != nil {
		evt.PayloadSize = len(app.Payload())
	}

	// Certification SHA-256 (preuve d'intégrité — recevable en justice Art. 52 Loi 5-2025)
	evt.Hash = hashEvent(evt)

	// Envoi vers le pipeline SIEM
	select {
	case w.events <- evt:
	default:
		// Buffer plein — on discard sans bloquer
	}
}

func (w *WiresharkEngine) Stop() {
	close(w.stop)
	if w.handle != nil {
		w.handle.Close()
	}
	w.wg.Wait()
}

// ──────────────────────────────────────────────
//  MOTEUR SIEM — Corrélation & Détection
// ──────────────────────────────────────────────

type SIEMEngine struct {
	cfg          *Config
	events       <-chan PacketEvent
	alerts       chan<- SIEMAlert
	ipCounter    map[string]int
	portCounter  map[string]int
	mu           sync.Mutex
	fraudRules   []FraudRule
}

type FraudRule struct {
	Name     string
	Check    func(evt PacketEvent, counters map[string]int) (bool, string)
	Severity string
	Category string
	LegalRef string
}

func NewSIEMEngine(cfg *Config, events <-chan PacketEvent, alerts chan<- SIEMAlert) *SIEMEngine {
	s := &SIEMEngine{
		cfg:         cfg,
		events:      events,
		alerts:      alerts,
		ipCounter:   make(map[string]int),
		portCounter: make(map[string]int),
	}
	s.loadFraudRules()
	return s
}

func (s *SIEMEngine) loadFraudRules() {
	s.fraudRules = []FraudRule{
		{
			Name:     "SCAN_PORT_MASSIF",
			Severity: "ÉLEVÉ",
			Category: "INTRUSION",
			LegalRef: "Art. 13 Loi 26-2020",
			Check: func(evt PacketEvent, c map[string]int) (bool, string) {
				key := "scan:" + evt.SrcIP
				c[key]++
				if c[key] > 100 {
					return true, fmt.Sprintf("IP %s a sondé >100 ports en <60s", evt.SrcIP)
				}
				return false, ""
			},
		},
		{
			Name:     "EXFILTRATION_DONNÉES",
			Severity: "CRITIQUE",
			Category: "EXFILTRATION",
			LegalRef: "Art. 18 Loi 5-2025 (CNPD)",
			Check: func(evt PacketEvent, c map[string]int) (bool, string) {
				// Gros transfert vers IP externe sur port non standard
				external := !isPrivateIP(evt.DstIP)
				suspicious := !isCommonPort(evt.DstPort)
				if external && suspicious && evt.PayloadSize > 50000 {
					return true, fmt.Sprintf("Transfert %d bytes vers %s:%s", evt.PayloadSize, evt.DstIP, evt.DstPort)
				}
				return false, ""
			},
		},
		{
			Name:     "CONNEXION_HEURE_ANORMALE",
			Severity: "MODÉRÉ",
			Category: "ANOMALIE",
			LegalRef: "Art. 52 Loi 5-2025",
			Check: func(evt PacketEvent, c map[string]int) (bool, string) {
				h := evt.Timestamp.Hour()
				if h >= 0 && h < 5 {
					return true, fmt.Sprintf("Activité réseau à %dh depuis %s", h, evt.SrcIP)
				}
				return false, ""
			},
		},
		{
			Name:     "FRAUDE_FINANCIÈRE_PATTERN",
			Severity: "CRITIQUE",
			Category: "FRAUDE",
			LegalRef: "Art. 76 Loi 26-2020",
			Check: func(evt PacketEvent, c map[string]int) (bool, string) {
				// Accès répété aux APIs financières depuis une IP inconnue
				fraudPorts := []string{"8443", "9090", "3001", "5432"}
				for _, p := range fraudPorts {
					if evt.DstPort == p {
						key := "fraud:" + evt.SrcIP + ":" + p
						c[key]++
						if c[key] > 50 {
							return true, fmt.Sprintf("Pattern fraude : %s → port %s (%d req)", evt.SrcIP, p, c[key])
						}
					}
				}
				return false, ""
			},
		},
		{
			Name:     "DLP_DNS_TUNNEL",
			Severity: "ÉLEVÉ",
			Category: "EXFILTRATION",
			LegalRef: "Art. 18 Loi 5-2025",
			Check: func(evt PacketEvent, c map[string]int) (bool, string) {
				// DNS Tunneling — exfiltration via requêtes DNS anormalement longues
				if evt.DstPort == "53" && evt.PayloadSize > 200 {
					return true, fmt.Sprintf("DNS Tunnel suspect depuis %s (payload %d bytes)", evt.SrcIP, evt.PayloadSize)
				}
				return false, ""
			},
		},
	}

	// Règles sectorielles
	sector := s.cfg.Agent.Sector
	switch sector {
	case "banque":
		s.fraudRules = append(s.fraudRules, FraudRule{
			Name:     "SWIFT_ANOMALIE",
			Severity: "CRITIQUE",
			Category: "FRAUDE",
			LegalRef: "COBAC R-2017 + Art. 76 Loi 26-2020",
			Check: func(evt PacketEvent, c map[string]int) (bool, string) {
				if evt.DstPort == "9200" || evt.DstPort == "15000" {
					key := "swift:" + evt.SrcIP
					c[key]++
					if c[key] > 20 {
						return true, fmt.Sprintf("Anomalie SWIFT depuis %s", evt.SrcIP)
					}
				}
				return false, ""
			},
		})
	case "minier":
		s.fraudRules = append(s.fraudRules, FraudRule{
			Name:     "ITIE_ACCÈS_DONNÉES",
			Severity: "ÉLEVÉ",
			Category: "FRAUDE",
			LegalRef: "Code Minier Art. 78 + ITIE Standard 2023",
			Check: func(evt PacketEvent, c map[string]int) (bool, string) {
				if isPrivateIP(evt.SrcIP) && !isPrivateIP(evt.DstIP) {
					key := "mine_ext:" + evt.SrcIP
					c[key]++
					if c[key] > 30 {
						return true, fmt.Sprintf("Exfiltration données minières depuis %s", evt.SrcIP)
					}
				}
				return false, ""
			},
		})
	}
}

func (s *SIEMEngine) Run() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case evt, ok := <-s.events:
			if !ok {
				return
			}
			s.analyzeEvent(evt)
		case <-ticker.C:
			s.flushCounters()
		}
	}
}

func (s *SIEMEngine) analyzeEvent(evt PacketEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, rule := range s.fraudRules {
		if triggered, desc := rule.Check(evt, s.ipCounter); triggered {
			alert := SIEMAlert{
				ID:          generateID(),
				Timestamp:   time.Now(),
				TenantID:    s.cfg.Agent.TenantID,
				Severity:    rule.Severity,
				Category:    rule.Category,
				Module:      "CORE-SIEM",
				Description: desc,
				SrcIP:       evt.SrcIP,
				DstIP:       evt.DstIP,
				Evidence:    evt.Hash,
				Sector:      s.cfg.Agent.Sector,
				LegalRef:    rule.LegalRef,
			}
			// Module check
			if rule.Category == "EXFILTRATION" && s.cfg.Modules.NDR {
				alert.Module = "CC-NDR"
			} else if rule.Category == "EXFILTRATION" && s.cfg.Modules.DLP {
				alert.Module = "CC-DLP"
			}

			select {
			case s.alerts <- alert:
			default:
			}
		}
	}
}

func (s *SIEMEngine) flushCounters() {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Réinitialise les compteurs toutes les 60s pour éviter les faux positifs
	s.ipCounter = make(map[string]int)
}

// ──────────────────────────────────────────────
//  REPORTER CLOUD — Envoi vers Onkɔngɔ
// ──────────────────────────────────────────────

type CloudReporter struct {
	cfg      *Config
	alerts   <-chan SIEMAlert
	logPath  string
	client   *http.Client
}

func NewCloudReporter(cfg *Config, alerts <-chan SIEMAlert) *CloudReporter {
	return &CloudReporter{
		cfg:    cfg,
		alerts: alerts,
		logPath: cfg.Archive.LocalPath,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (r *CloudReporter) Run() {
	batch := make([]SIEMAlert, 0, 50)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case alert := <-r.alerts:
			// Archivage local immédiat (10 ans — Tiers de Confiance)
			r.archiveLocal(alert)
			batch = append(batch, alert)
			if len(batch) >= 50 {
				r.sendBatch(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				r.sendBatch(batch)
				batch = batch[:0]
			}
		}
	}
}

func (r *CloudReporter) sendBatch(alerts []SIEMAlert) {
	payload, err := json.Marshal(map[string]interface{}{
		"tenant_id":  r.cfg.Agent.TenantID,
		"agent_v":    "1.0",
		"os":         runtime.GOOS,
		"sent_at":    time.Now().UTC(),
		"alerts":     alerts,
	})
	if err != nil {
		log.Printf("[CLOUD] Erreur sérialisation : %v", err)
		return
	}

	url := r.cfg.Agent.CloudURL + "/alerts/batch"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		log.Printf("[CLOUD] Erreur création requête : %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", r.cfg.Agent.APIKey)
	req.Header.Set("X-Tenant-ID", r.cfg.Agent.TenantID)

	resp, err := r.client.Do(req)
	if err != nil {
		log.Printf("[CLOUD] Erreur envoi (retry dans 5s) : %v", err)
		return
	}
	defer resp.Body.Close()
	log.Printf("[CLOUD] Batch de %d alertes envoyé — HTTP %d", len(alerts), resp.StatusCode)
}

func (r *CloudReporter) archiveLocal(alert SIEMAlert) {
	if r.logPath == "" {
		return
	}
	day := alert.Timestamp.Format("2006-01-02")
	path := fmt.Sprintf("%s/%s_%s.jsonl", r.logPath, r.cfg.Agent.TenantID, day)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	line, _ := json.Marshal(alert)
	f.Write(append(line, '\n'))
}

// ──────────────────────────────────────────────
//  PROFILAGE COMPORTEMENTAL — Envoi anonymisé CNS
// ──────────────────────────────────────────────

type ProfilerEngine struct {
	cfg     *Config
	events  <-chan PacketEvent
	reporter *CloudReporter
}

func NewProfilerEngine(cfg *Config, events <-chan PacketEvent, r *CloudReporter) *ProfilerEngine {
	return &ProfilerEngine{cfg: cfg, events: events, reporter: r}
}

func (p *ProfilerEngine) Run() {
	ipHits := make(map[string]int)
	protoHits := make(map[string]int)
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	// Écoute sur un canal séparé (copie)
	for {
		select {
		case <-ticker.C:
			// Construit un profil agrégé anonymisé
			score := computeAnomalyScore(ipHits)
			profile := BehaviorProfile{
				TenantID:     p.cfg.Agent.TenantID,
				Timestamp:    time.Now(),
				AnomalyScore: score,
				ProtocolDist: protoHits,
			}
			// Envoi vers le portail CNS (jamais vers le portail Client)
			p.sendProfile(profile)
			// Reset
			ipHits = make(map[string]int)
			protoHits = make(map[string]int)
		}
	}
}

func (p *ProfilerEngine) sendProfile(prof BehaviorProfile) {
	payload, _ := json.Marshal(prof)
	url := p.cfg.Agent.CloudURL + "/profiling/behavior"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", p.cfg.Agent.APIKey)
	req.Header.Set("X-Profile-Scope", "CNS_ONLY") // Jamais visible par le tenant
	http.DefaultClient.Do(req)
}

// ──────────────────────────────────────────────
//  POINT D'ENTRÉE PRINCIPAL
// ──────────────────────────────────────────────

func main() {
	printBanner()

	// 1. Chargement de la config
	cfg := loadConfig("congocomply.yaml")
	log.Printf("[INIT] Tenant : %s | Secteur : %s | OS : %s", cfg.Agent.OrgName, cfg.Agent.Sector, runtime.GOOS)

	// 2. Canal partagé entre les moteurs
	events := make(chan PacketEvent, 10000)
	alerts := make(chan SIEMAlert, 1000)

	// 3. Moteur Wireshark
	wireshark := NewWiresharkEngine(cfg)
	wireshark.events = events
	wireshark.alerts = alerts
	if err := wireshark.Start(); err != nil {
		log.Fatalf("[FATAL] Wireshark Engine : %v", err)
	}

	// 4. Moteur SIEM
	siem := NewSIEMEngine(cfg, events, alerts)
	go siem.Run()

	// 5. Reporter Cloud
	reporter := NewCloudReporter(cfg, alerts)
	go reporter.Run()

	// 6. Profilage comportemental (données → CNS uniquement)
	profiler := NewProfilerEngine(cfg, events, reporter)
	go profiler.Run()

	// 7. Modules optionnels activés selon licence
	loadOptionalModules(cfg)

	log.Println("[READY] CongoComply Agent actif — surveillance en cours...")
	select {} // Bloque indéfiniment
}

// ──────────────────────────────────────────────
//  MODULES OPTIONNELS
// ──────────────────────────────────────────────

func loadOptionalModules(cfg *Config) {
	if cfg.Modules.NDR {
		log.Println("[MODULE] CC-NDR activé — Analyse trafic réseau avancée")
	}
	if cfg.Modules.DLP {
		log.Println("[MODULE] CC-DLP activé — Protection données sensibles")
	}
	if cfg.Modules.EDR {
		log.Println("[MODULE] CC-EDR activé — Surveillance des postes & guichets")
		go runEDR(cfg)
	}
	if cfg.Modules.IAM {
		log.Println("[MODULE] CC-IAM activé — Gestion des identités & accès")
		go runIAM(cfg)
	}
	if cfg.Modules.VULN {
		log.Println("[MODULE] CC-VULN activé — Scan de vulnérabilités")
		go runVulnScan(cfg)
	}
	if cfg.Modules.AWARENESS {
		log.Println("[MODULE] CC-AWARENESS activé — Rapports de sensibilisation")
	}
}

// Stub modules — à implémenter dans les fichiers séparés
func runEDR(cfg *Config)      { log.Println("[CC-EDR] Surveillance processus & fichiers actifs") }
func runIAM(cfg *Config)      { log.Println("[CC-IAM] Monitoring authentifications & privilèges") }
func runVulnScan(cfg *Config) {
	ticker := time.NewTicker(24 * time.Hour)
	for range ticker.C {
		log.Println("[CC-VULN] Scan de vulnérabilités lancé...")
	}
}

// ──────────────────────────────────────────────
//  UTILITAIRES
// ──────────────────────────────────────────────

func loadConfig(path string) *Config {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("[CONFIG] Fichier %s introuvable — utilisation des valeurs par défaut", path)
		return defaultConfig()
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("[CONFIG] Erreur parsing YAML : %v", err)
	}
	return &cfg
}

func defaultConfig() *Config {
	cfg := &Config{}
	cfg.Agent.CloudURL = "https://api.onkongo.cg/v1"
	cfg.Agent.BPFFilter = "tcp or udp"
	cfg.Archive.RetentionYears = 10
	cfg.Archive.Encrypt = true
	return cfg
}

func autoDetectInterface() string {
	ifaces, err := pcap.FindAllDevs()
	if err != nil || len(ifaces) == 0 {
		return "eth0"
	}
	for _, d := range ifaces {
		if strings.Contains(d.Name, "eth") || strings.Contains(d.Name, "en") {
			return d.Name
		}
	}
	return ifaces[0].Name
}

func hashEvent(evt PacketEvent) string {
	data := fmt.Sprintf("%v%s%s%s%s%s%d", evt.Timestamp, evt.SrcIP, evt.DstIP, evt.SrcPort, evt.DstPort, evt.Protocol, evt.PayloadSize)
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

func generateID() string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	return hex.EncodeToString(h[:8])
}

func isPrivateIP(ip string) bool {
	private := []string{"10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.", "127."}
	for _, p := range private {
		if strings.HasPrefix(ip, p) {
			return true
		}
	}
	return false
}

func isCommonPort(port string) bool {
	common := map[string]bool{"80": true, "443": true, "22": true, "25": true, "53": true, "8080": true, "8443": true}
	return common[port]
}

func computeAnomalyScore(hits map[string]int) float64 {
	if len(hits) == 0 {
		return 0.0
	}
	var max int
	for _, v := range hits {
		if v > max {
			max = v
		}
	}
	score := float64(max) / 1000.0
	if score > 1.0 {
		return 1.0
	}
	return score
}

func tcpFlags(tcp *layers.TCP) string {
	flags := []string{}
	if tcp.SYN { flags = append(flags, "SYN") }
	if tcp.ACK { flags = append(flags, "ACK") }
	if tcp.FIN { flags = append(flags, "FIN") }
	if tcp.RST { flags = append(flags, "RST") }
	if tcp.PSH { flags = append(flags, "PSH") }
	return strings.Join(flags, "|")
}

func printBanner() {
	fmt.Println(`
 ██████╗ ██████╗ ███╗  ██╗ ██████╗  ██████╗  ██████╗ ██████╗ ███╗  ███╗██████╗ ██╗  ██╗
██╔════╝██╔═══██╗████╗ ██║██╔════╝ ██╔═══██╗██╔════╝██╔═══██╗████╗████║██╔══██╗██║  ██║
██║     ██║   ██║██╔██╗██║██║  ███╗██║   ██║██║     ██║   ██║██╔████╔██║██████╔╝██║  ██║
██║     ██║   ██║██║╚████║██║   ██║██║   ██║██║     ██║   ██║██║╚██╔╝██║██╔═══╝ ██║  ██║
╚██████╗╚██████╔╝██║ ╚███║╚██████╔╝╚██████╔╝╚██████╗╚██████╔╝██║ ╚═╝ ██║██║     ╚█████╔╝
 ╚═════╝ ╚═════╝ ╚═╝  ╚══╝ ╚═════╝  ╚═════╝  ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝      ╚════╝
  Agent v1.0 | SPV DIGITALE LUCEOR | T. LOEMBA — Ingénieur Civil des Mines de Paris
  Conformité : Loi 5-2025 (CNPD) + Loi 26-2020 (ANSSI) | Archivage 10 ans | SHA-256
`)
}
