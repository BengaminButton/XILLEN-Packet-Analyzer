package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type PacketInfo struct {
	Timestamp   time.Time `json:"timestamp"`
	SourceIP    string    `json:"source_ip"`
	DestIP      string    `json:"dest_ip"`
	SourcePort  uint16    `json:"source_port"`
	DestPort    uint16    `json:"dest_port"`
	Protocol    string    `json:"protocol"`
	Length      int       `json:"length"`
	TTL         uint8     `json:"ttl"`
	Flags       string    `json:"flags"`
	Payload     string    `json:"payload"`
	HTTPMethod  string    `json:"http_method,omitempty"`
	HTTPHost    string    `json:"http_host,omitempty"`
	HTTPPath    string    `json:"http_path,omitempty"`
	DNSQuery    string    `json:"dns_query,omitempty"`
	DNSResponse string    `json:"dns_response,omitempty"`
}

type XillenPacketAnalyzer struct {
	interfaceName string
	filter        string
	outputFile    string
	verbose       bool
	packetCount   int
	maxPackets    int
	packets       []PacketInfo
	mutex         sync.RWMutex
	stats         map[string]int
}

func NewXillenPacketAnalyzer() *XillenPacketAnalyzer {
	return &XillenPacketAnalyzer{
		stats: make(map[string]int),
	}
}

func (pa *XillenPacketAnalyzer) showBanner() {
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                  XILLEN Packet Analyzer                    ║")
	fmt.Println("║                      v2.0 by @Bengamin_Button              ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

func (pa *XillenPacketAnalyzer) listInterfaces() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal("Error finding devices:", err)
	}

	fmt.Println("Available network interfaces:")
	fmt.Println("─".repeat(50))
	for i, device := range devices {
		fmt.Printf("%d. %s\n", i+1, device.Name)
		if len(device.Description) > 0 {
			fmt.Printf("   Description: %s\n", device.Description)
		}
		fmt.Printf("   Addresses: %d\n", len(device.Addresses))
		for _, address := range device.Addresses {
			fmt.Printf("     %s: %s\n", address.IP, address.Netmask)
		}
		fmt.Println()
	}
}

func (pa *XillenPacketAnalyzer) startCapture() {
	if pa.interfaceName == "" {
		log.Fatal("Interface name not specified")
	}

	handle, err := pcap.OpenLive(pa.interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("Error opening interface:", err)
	}
	defer handle.Close()

	if pa.filter != "" {
		err = handle.SetBPFFilter(pa.filter)
		if err != nil {
			log.Fatal("Error setting BPF filter:", err)
		}
	}

	fmt.Printf("Starting capture on interface: %s\n", pa.interfaceName)
	if pa.filter != "" {
		fmt.Printf("BPF Filter: %s\n", pa.filter)
	}
	fmt.Printf("Max packets: %d\n", pa.maxPackets)
	fmt.Println("Press Ctrl+C to stop capture")
	fmt.Println()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	for packet := range packets {
		pa.processPacket(packet)
		pa.packetCount++

		if pa.maxPackets > 0 && pa.packetCount >= pa.maxPackets {
			break
		}
	}

	pa.showStatistics()
}

func (pa *XillenPacketAnalyzer) processPacket(packet gopacket.Packet) {
	packetInfo := PacketInfo{
		Timestamp: time.Now(),
		Length:    len(packet.Data()),
	}

	networkLayer := packet.NetworkLayer()
	if networkLayer != nil {
		switch v := networkLayer.(type) {
		case *layers.IPv4:
			packetInfo.SourceIP = v.SrcIP.String()
			packetInfo.DestIP = v.DstIP.String()
			packetInfo.TTL = v.TTL
			packetInfo.Protocol = "IPv4"
		case *layers.IPv6:
			packetInfo.SourceIP = v.SrcIP.String()
			packetInfo.DestIP = v.DstIP.String()
			packetInfo.Protocol = "IPv6"
		}
	}

	transportLayer := packet.TransportLayer()
	if transportLayer != nil {
		switch v := transportLayer.(type) {
		case *layers.TCP:
			packetInfo.SourcePort = uint16(v.SrcPort)
			packetInfo.DestPort = uint16(v.DestPort)
			packetInfo.Protocol = "TCP"
			packetInfo.Flags = pa.getTCPFlags(v)
		case *layers.UDP:
			packetInfo.SourcePort = uint16(v.SrcPort)
			packetInfo.DestPort = uint16(v.DestPort)
			packetInfo.Protocol = "UDP"
		case *layers.ICMPv4:
			packetInfo.Protocol = "ICMPv4"
		case *layers.ICMPv6:
			packetInfo.Protocol = "ICMPv6"
		}
	}

	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		pa.analyzeApplicationLayer(applicationLayer, &packetInfo)
	}

	pa.addPacket(packetInfo)
	pa.updateStats(packetInfo.Protocol)

	if pa.verbose {
		pa.printPacketInfo(packetInfo)
	}
}

func (pa *XillenPacketAnalyzer) getTCPFlags(tcp *layers.TCP) string {
	var flags []string
	if tcp.SYN {
		flags = append(flags, "SYN")
	}
	if tcp.ACK {
		flags = append(flags, "ACK")
	}
	if tcp.FIN {
		flags = append(flags, "FIN")
	}
	if tcp.RST {
		flags = append(flags, "RST")
	}
	if tcp.PSH {
		flags = append(flags, "PSH")
	}
	if tcp.URG {
		flags = append(flags, "URG")
	}
	return strings.Join(flags, ",")
}

func (pa *XillenPacketAnalyzer) analyzeApplicationLayer(app gopacket.ApplicationLayer, info *PacketInfo) {
	payload := string(app.Payload())
	info.Payload = payload

	if strings.HasPrefix(payload, "GET ") || strings.HasPrefix(payload, "POST ") ||
		strings.HasPrefix(payload, "PUT ") || strings.HasPrefix(payload, "DELETE ") ||
		strings.HasPrefix(payload, "HEAD ") || strings.HasPrefix(payload, "OPTIONS ") {
		pa.parseHTTP(payload, info)
	} else if strings.Contains(payload, "HTTP/1.") {
		pa.parseHTTPResponse(payload, info)
	} else if info.DestPort == 53 || info.SourcePort == 53 {
		pa.parseDNS(app.Payload(), info)
	}
}

func (pa *XillenPacketAnalyzer) parseHTTP(payload string, info *PacketInfo) {
	lines := strings.Split(payload, "\r\n")
	if len(lines) > 0 {
		parts := strings.Split(lines[0], " ")
		if len(parts) >= 3 {
			info.HTTPMethod = parts[0]
			info.HTTPPath = parts[1]
		}
	}

	for _, line := range lines {
		if strings.HasPrefix(line, "Host: ") {
			info.HTTPHost = strings.TrimPrefix(line, "Host: ")
			break
		}
	}
}

func (pa *XillenPacketAnalyzer) parseHTTPResponse(payload string, info *PacketInfo) {
	lines := strings.Split(payload, "\r\n")
	if len(lines) > 0 {
		parts := strings.Split(lines[0], " ")
		if len(parts) >= 2 {
			info.HTTPMethod = "RESPONSE"
			info.HTTPPath = parts[1]
		}
	}
}

func (pa *XillenPacketAnalyzer) parseDNS(payload []byte, info *PacketInfo) {
	if len(payload) < 12 {
		return
	}

	flags := binary.BigEndian.Uint16(payload[2:4])
	isQuery := (flags & 0x8000) == 0

	if isQuery {
		info.DNSQuery = pa.extractDNSName(payload[12:])
	} else {
		info.DNSResponse = pa.extractDNSName(payload[12:])
	}
}

func (pa *XillenPacketAnalyzer) extractDNSName(data []byte) string {
	var name strings.Builder
	pos := 0

	for pos < len(data) && data[pos] != 0 {
		length := int(data[pos])
		pos++
		if pos+length > len(data) {
			break
		}
		if name.Len() > 0 {
			name.WriteByte('.')
		}
		name.Write(data[pos : pos+length])
		pos += length
	}

	return name.String()
}

func (pa *XillenPacketAnalyzer) addPacket(info PacketInfo) {
	pa.mutex.Lock()
	defer pa.mutex.Unlock()
	pa.packets = append(pa.packets, info)
}

func (pa *XillenPacketAnalyzer) updateStats(protocol string) {
	pa.mutex.Lock()
	defer pa.mutex.Unlock()
	pa.stats[protocol]++
}

func (pa *XillenPacketAnalyzer) printPacketInfo(info PacketInfo) {
	fmt.Printf("[%s] %s:%d -> %s:%d (%s) Length: %d\n",
		info.Timestamp.Format("15:04:05.000"),
		info.SourceIP, info.SourcePort,
		info.DestIP, info.DestPort,
		info.Protocol, info.Length)

	if info.HTTPMethod != "" {
		fmt.Printf("  HTTP: %s %s\n", info.HTTPMethod, info.HTTPPath)
		if info.HTTPHost != "" {
			fmt.Printf("  Host: %s\n", info.HTTPHost)
		}
	}

	if info.DNSQuery != "" {
		fmt.Printf("  DNS Query: %s\n", info.DNSQuery)
	}

	if info.DNSResponse != "" {
		fmt.Printf("  DNS Response: %s\n", info.DNSResponse)
	}

	if info.Flags != "" {
		fmt.Printf("  TCP Flags: %s\n", info.Flags)
	}

	fmt.Println()
}

func (pa *XillenPacketAnalyzer) showStatistics() {
	fmt.Println("\n=== Capture Statistics ===")
	fmt.Printf("Total packets captured: %d\n", pa.packetCount)
	fmt.Println("\nProtocol breakdown:")

	pa.mutex.RLock()
	defer pa.mutex.RUnlock()

	for protocol, count := range pa.stats {
		percentage := float64(count) / float64(pa.packetCount) * 100
		fmt.Printf("  %s: %d (%.1f%%)\n", protocol, count, percentage)
	}
}

func (pa *XillenPacketAnalyzer) saveToFile() {
	if pa.outputFile == "" {
		return
	}

	pa.mutex.RLock()
	defer pa.mutex.RUnlock()

	file, err := os.Create(pa.outputFile)
	if err != nil {
		log.Printf("Error creating output file: %v", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	err = encoder.Encode(pa.packets)
	if err != nil {
		log.Printf("Error encoding packets: %v", err)
		return
	}

	fmt.Printf("Packets saved to: %s\n", pa.outputFile)
}

func (pa *XillenPacketAnalyzer) exportToCSV() {
	if pa.outputFile == "" {
		pa.outputFile = "packets.csv"
	}

	pa.mutex.RLock()
	defer pa.mutex.RUnlock()

	file, err := os.Create(pa.outputFile)
	if err != nil {
		log.Printf("Error creating CSV file: %v", err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	writer.WriteString("Timestamp,SourceIP,DestIP,SourcePort,DestPort,Protocol,Length,TTL,Flags,HTTPMethod,HTTPHost,HTTPPath,DNSQuery,DNSResponse\n")

	for _, packet := range pa.packets {
		line := fmt.Sprintf("%s,%s,%s,%d,%d,%s,%d,%d,%s,%s,%s,%s,%s,%s\n",
			packet.Timestamp.Format("2006-01-02 15:04:05.000"),
			packet.SourceIP, packet.DestIP,
			packet.SourcePort, packet.DestPort,
			packet.Protocol, packet.Length, packet.TTL,
			packet.Flags, packet.HTTPMethod, packet.HTTPHost,
			packet.HTTPPath, packet.DNSQuery, packet.DNSResponse)
		writer.WriteString(line)
	}

	fmt.Printf("Packets exported to CSV: %s\n", pa.outputFile)
}

func (pa *XillenPacketAnalyzer) showHelp() {
	fmt.Println("Usage: xillen-packet-analyzer [options]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -i, --interface <name>    Network interface to capture")
	fmt.Println("  -f, --filter <filter>     BPF filter (e.g., 'tcp port 80')")
	fmt.Println("  -o, --output <file>       Output file for results")
	fmt.Println("  -c, --count <number>      Maximum number of packets to capture")
	fmt.Println("  -v, --verbose             Verbose output")
	fmt.Println("  -l, --list                List available interfaces")
	fmt.Println("  -h, --help                Show this help message")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  xillen-packet-analyzer -i eth0")
	fmt.Println("  xillen-packet-analyzer -i eth0 -f 'tcp port 80' -c 1000")
	fmt.Println("  xillen-packet-analyzer -i eth0 -o results.json -v")
}

func main() {
	pa := NewXillenPacketAnalyzer()
	pa.showBanner()

	var (
		interfaceName  = flag.String("i", "", "Network interface to capture")
		filter         = flag.String("f", "", "BPF filter")
		outputFile     = flag.String("o", "", "Output file")
		maxPackets     = flag.Int("c", 0, "Maximum number of packets to capture")
		verbose        = flag.Bool("v", false, "Verbose output")
		listInterfaces = flag.Bool("l", false, "List available interfaces")
		help           = flag.Bool("h", false, "Show help")
	)

	flag.Parse()

	if *help {
		pa.showHelp()
		return
	}

	if *listInterfaces {
		pa.listInterfaces()
		return
	}

	if *interfaceName == "" {
		fmt.Println("Error: Interface name is required")
		fmt.Println("Use -h for help")
		return
	}

	pa.interfaceName = *interfaceName
	pa.filter = *filter
	pa.outputFile = *outputFile
	pa.verbose = *verbose
	pa.maxPackets = *maxPackets

	defer func() {
		if pa.outputFile != "" {
			if strings.HasSuffix(pa.outputFile, ".csv") {
				pa.exportToCSV()
			} else {
				pa.saveToFile()
			}
		}
	}()

	pa.startCapture()
}

