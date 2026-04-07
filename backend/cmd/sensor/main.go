package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type Config struct {
	ServerURL    string   `json:"server_url"`
	SensorID     string   `json:"sensor_id"`
	ListenPort   int      `json:"listen_port"`
	SampledPorts []string `json:"sampled_ports"`
	ThresholdMB  int      `json:"threshold_mb"`
}

type NetworkFlow struct {
	Timestamp   string  `json:"timestamp"`
	SourceIP    string  `json:"source_ip"`
	SourcePort  int     `json:"source_port"`
	DestIP      string  `json:"dest_ip"`
	DestPort    int     `json:"dest_port"`
	Protocol    string  `json:"protocol"`
	BytesIn     int64   `json:"bytes_in"`
	BytesOut    int64   `json:"bytes_out"`
	Packets     int     `json:"packets"`
	Duration    float64 `json:"duration"`
	AppProtocol string  `json:"app_protocol"`
	Direction   string  `json:"direction"`
	SensorID    string  `json:"sensor_id"`
}

type Alert struct {
	AlertType string      `json:"alert_type"`
	Severity  string      `json:"severity"`
	Message   string      `json:"message"`
	Flow      NetworkFlow `json:"flow"`
	Timestamp string      `json:"timestamp"`
}

var config Config

var knownPorts = map[int]string{
	20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
	25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
	143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
	995: "POP3S", 1433: "MSSQL", 3306: "MYSQL", 5432: "POSTGRESQL",
	6379: "REDIS", 8080: "HTTP-PROXY", 8443: "HTTPS-ALT",
}

var sensitiveProtocols = []string{"FTP", "TELNET", "SMB"}
var suspiciousPorts = []int{4444, 5555, 6666, 31337, 12345, 54321}

func loadConfig() {
	configData := os.Getenv("SENSOR_CONFIG")
	if configData == "" {
		config = Config{
			ServerURL:    "http://localhost:8000",
			SensorID:     "net-sensor-" + time.Now().Format("0601021504"),
			ListenPort:   5140,
			SampledPorts: []string{"80", "443", "22", "21", "25"},
			ThresholdMB:  100,
		}
	} else {
		json.Unmarshal([]byte(configData), &config)
	}
}

func getProtocol(port int) string {
	if proto, ok := knownPorts[port]; ok {
		return proto
	}
	return "UNKNOWN"
}

func isSensitiveProtocol(protocol string) bool {
	for _, sp := range sensitiveProtocols {
		if protocol == sp {
			return true
		}
	}
	return false
}

func isSuspiciousPort(port int) bool {
	for _, sp := range suspiciousPorts {
		if port == sp {
			return true
		}
	}
	return false
}

func isExternalIP(ip string) bool {
	if strings.HasPrefix(ip, "10.") {
		return false
	}
	if strings.HasPrefix(ip, "192.168.") {
		return false
	}
	if strings.HasPrefix(ip, "172.16.") {
		return false
	}
	return true
}

func processFlow(flow NetworkFlow) []Alert {
	var alerts []Alert

	if isSensitiveProtocol(flow.Protocol) {
		alerts = append(alerts, Alert{
			AlertType: "sensitive_protocol",
			Severity:  "high",
			Message:   fmt.Sprintf("Sensitive protocol %s detected", flow.Protocol),
			Flow:      flow,
			Timestamp: time.Now().Format(time.RFC3339),
		})
	}

	if flow.BytesOut > int64(config.ThresholdMB)*1024*1024 {
		severity := "high"
		if flow.BytesOut > int64(config.ThresholdMB)*10*1024*1024 {
			severity = "critical"
		}
		alerts = append(alerts, Alert{
			AlertType: "large_upload",
			Severity:  severity,
			Message:   fmt.Sprintf("Large data upload detected: %.1fMB", float64(flow.BytesOut)/1024/1024),
			Flow:      flow,
			Timestamp: time.Now().Format(time.RFC3339),
		})
	}

	if isSuspiciousPort(flow.DestPort) {
		alerts = append(alerts, Alert{
			AlertType: "suspicious_port",
			Severity:  "medium",
			Message:   fmt.Sprintf("Connection to suspicious port %d", flow.DestPort),
			Flow:      flow,
			Timestamp: time.Now().Format(time.RFC3339),
		})
	}

	if isExternalIP(flow.DestIP) && flow.BytesOut > 10*1024*1024 {
		alerts = append(alerts, Alert{
			AlertType: "external_transfer",
			Severity:  "high",
			Message:   fmt.Sprintf("Large transfer to external IP %s", flow.DestIP),
			Flow:      flow,
			Timestamp: time.Now().Format(time.RFC3339),
		})
	}

	return alerts
}

func sendFlow(flow NetworkFlow) {
	alerts := processFlow(flow)

	body, _ := json.Marshal(flow)
	resp, err := http.Post(
		fmt.Sprintf("%s/api/agents/network/flow", config.ServerURL),
		"application/json",
		strings.NewReader(string(body)),
	)
	if err == nil {
		defer resp.Body.Close()
	}

	for _, alert := range alerts {
		sendAlert(alert)
	}
}

func sendAlert(alert Alert) {
	body, _ := json.Marshal(alert)
	resp, err := http.Post(
		fmt.Sprintf("%s/api/agents/network/alert", config.ServerURL),
		"application/json",
		strings.NewReader(string(body)),
	)
	if err != nil {
		log.Printf("Failed to send alert: %v", err)
	} else {
		defer resp.Body.Close()
		log.Printf("Alert sent: %s - %s", alert.AlertType, alert.Message)
	}
}

func simulateTraffic() {
	sampleFlows := []NetworkFlow{
		{SourceIP: "192.168.1.100", DestIP: "10.0.0.5", DestPort: 443, Protocol: "HTTPS", BytesOut: 50000},
		{SourceIP: "192.168.1.105", DestIP: "172.16.0.10", DestPort: 22, Protocol: "SSH", BytesOut: 2048},
		{SourceIP: "192.168.1.110", DestIP: "8.8.8.8", DestPort: 53, Protocol: "DNS", BytesOut: 256},
		{SourceIP: "192.168.1.120", DestIP: "185.199.108.153", DestPort: 21, Protocol: "FTP", BytesOut: 52428800},
	}

	for {
		for i := range sampleFlows {
			flow := sampleFlows[i]
			flow.Timestamp = time.Now().Format(time.RFC3339)
			flow.SensorID = config.SensorID
			flow.AppProtocol = getProtocol(flow.DestPort)
			flow.Direction = "outbound"
			flow.Packets = 1
			flow.Duration = 0.5

			sendFlow(flow)
		}
		time.Sleep(5 * time.Second)
	}
}

func healthCheck() {
	for {
		resp, err := http.Get(fmt.Sprintf("%s/health", config.ServerURL))
		if err != nil {
			log.Printf("Server unreachable: %v", err)
		} else {
			resp.Body.Close()
		}
		time.Sleep(30 * time.Second)
	}
}

func main() {
	loadConfig()

	log.Printf("Starting Network Sensor: %s", config.SensorID)
	log.Printf("Threshold: %d MB", config.ThresholdMB)

	go healthCheck()
	simulateTraffic()
}
