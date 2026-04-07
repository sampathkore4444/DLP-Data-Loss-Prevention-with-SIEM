package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

type Config struct {
	ServerURL    string   `json:"server_url"`
	AgentID      string   `json:"agent_id"`
	Hostname     string   `json:"hostname"`
	WatchPaths   []string `json:"watch_paths"`
	SensitiveExt []string `json:"sensitive_ext"`
	Interval     int      `json:"interval"`
}

type FileEvent struct {
	EventType string `json:"event_type"`
	FilePath  string `json:"file_path"`
	FileName  string `json:"file_name"`
	FileSize  int64  `json:"file_size"`
	FileHash  string `json:"file_hash"`
	Timestamp string `json:"timestamp"`
	Channel   string `json:"channel"`
	AgentID   string `json:"agent_id"`
	Hostname  string `json:"hostname"`
	Action    string `json:"action"`
}

var (
	config      Config
	sensitiveRe *regexp.Regexp
	fileStates  = make(map[string]int64)
)

func loadConfig() {
	configData := os.Getenv("AGENT_CONFIG")
	if configData == "" {
		config = Config{
			ServerURL:    "http://localhost:8000",
			AgentID:      "endpoint-" + getShortID(),
			Hostname:     getHostname(),
			WatchPaths:   getDefaultWatchPaths(),
			SensitiveExt: []string{".xlsx", ".xls", ".csv", ".doc", ".docx", ".pdf", ".txt", ".json", ".xml", ".sql", ".bak"},
			Interval:     5,
		}
	} else {
		json.Unmarshal([]byte(configData), &config)
	}

	exts := make([]string, len(config.SensitiveExt))
	for i, ext := range config.SensitiveExt {
		exts[i] = strings.ToLower(ext)
	}
	sensitiveRe = regexp.MustCompile(`(?i)(` + strings.Join(exts, "|") + `)$`)
}

func getDefaultWatchPaths() []string {
	if runtime.GOOS == "windows" {
		return []string{"E:", "F:", "G:", "D:"}
	}
	return []string{"/media", "/mnt", "/Volumes", "/tmp"}
}

func getHostname() string {
	if runtime.GOOS == "windows" {
		return os.Getenv("COMPUTERNAME")
	}
	hostname, _ := os.Hostname()
	return hostname
}

func getShortID() string {
	return time.Now().Format("0601021504")
}

func isSensitiveFile(filename string) bool {
	return sensitiveRe.MatchString(filename)
}

func detectChannel(path string) string {
	path = strings.ToLower(path)
	if strings.Contains(path, "/media") || strings.Contains(path, ":") {
		return "usb"
	}
	if strings.Contains(path, "spool") {
		return "print"
	}
	return "local"
}

func watchLoop() {
	ticker := time.NewTicker(time.Duration(config.Interval) * time.Second)
	defer ticker.Stop()

	for {
		for _, watchPath := range config.WatchPaths {
			if _, err := os.Stat(watchPath); err == nil {
				scanDirectory(watchPath)
			}
		}
		<-ticker.C
	}
}

func scanDirectory(dir string) {
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}

		if !isSensitiveFile(info.Name()) {
			return nil
		}

		channel := detectChannel(path)
		modTime := info.ModTime().Unix()

		if _, exists := fileStates[path]; !exists {
			fileStates[path] = modTime
			sendEvent("created", path, info, channel)
		} else if fileStates[path] != modTime {
			fileStates[path] = modTime
			sendEvent("modified", path, info, channel)
		}

		return nil
	})
}

func sendEvent(eventType, path string, info os.FileInfo, channel string) {
	event := FileEvent{
		EventType: eventType,
		FilePath:  path,
		FileName:  info.Name(),
		FileSize:  info.Size(),
		Timestamp: time.Now().Format(time.RFC3339),
		Channel:   channel,
		AgentID:   config.AgentID,
		Hostname:  config.Hostname,
		Action:    "allow",
	}

	event.FileHash = fmt.Sprintf("%x", hash(path))

	body, _ := json.Marshal(event)
	resp, err := http.Post(
		fmt.Sprintf("%s/api/agents/endpoint/event", config.ServerURL),
		"application/json",
		strings.NewReader(string(body)),
	)

	if err != nil {
		log.Printf("Failed to send event: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		log.Printf("Server returned status: %d", resp.StatusCode)
	}
}

func hash(path string) int64 {
	file, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer file.Close()

	data := make([]byte, 1024)
	n, _ := file.Read(data)

	var sum int64
	for i := 0; i < n; i++ {
		sum += int64(data[i])
	}
	return sum
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

	log.Printf("Starting Endpoint Agent: %s on %s", config.AgentID, config.Hostname)
	log.Printf("Watching paths: %v", config.WatchPaths)

	go healthCheck()
	watchLoop()
}
