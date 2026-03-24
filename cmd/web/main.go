package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Server serves the web UI and API for chain analysis results
type Server struct {
	port     int
	staticDir string
	apiDir   string
}

// NewServer creates a new server
func NewServer(port int) *Server {
	return &Server{
		port:     port,
		staticDir: "web/ui",
		apiDir:   "out",
	}
}

// Start starts the web server
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/blocks", s.handleGetBlocks)
	mux.HandleFunc("/api/block/", s.handleGetBlock)

	// Static files (embed or serve from disk)
	mux.Handle("/", s.serveStaticOrAPI(http.FileServer(http.Dir(s.staticDir))))

	addr := fmt.Sprintf("127.0.0.1:%d", s.port)
	fmt.Printf("http://%s\n", addr)

	return http.ListenAndServe(addr, mux)
}

// handleHealth returns health status
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// handleGetBlocks returns list of available blocks
func (s *Server) handleGetBlocks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	files, err := os.ReadDir(s.apiDir)
	if err != nil {
		http.Error(w, "Failed to read blocks", http.StatusInternalServerError)
		return
	}

	var blocks []string
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".json") {
			blocks = append(blocks, strings.TrimSuffix(file.Name(), ".json"))
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":     true,
		"blocks": blocks,
	})
}

// handleGetBlock returns analysis for a specific block
func (s *Server) handleGetBlock(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	blockName := strings.TrimPrefix(r.URL.Path, "/api/block/")
	if blockName == "" {
		http.Error(w, "Missing block name", http.StatusBadRequest)
		return
	}

	// Read the JSON file
	filepath := filepath.Join(s.apiDir, blockName+".json")
	data, err := os.ReadFile(filepath)
	if err != nil {
		http.Error(w, "Block not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// serveStaticOrAPI serves static files or falls back to index.html
func (s *Server) serveStaticOrAPI(fileServer http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If path starts with /api, don't serve as static file
		if strings.HasPrefix(r.URL.Path, "/api") {
			http.NotFound(w, r)
			return
		}

		// Try to serve the file
		path := filepath.Join(s.staticDir, r.URL.Path)
		if _, err := os.Stat(path); err == nil {
			fileServer.ServeHTTP(w, r)
			return
		}

		// Fall back to index.html for routing
		indexPath := filepath.Join(s.staticDir, "index.html")
		if _, err := os.Stat(indexPath); err == nil {
			data, _ := os.ReadFile(indexPath)
			w.Header().Set("Content-Type", "text/html")
			w.Write(data)
			return
		}

		// Return default HTML
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<!DOCTYPE html>
<html>
<head>
	<title>Sherlock - Bitcoin Chain Analysis</title>
	<style>
		body { font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }
		h1 { color: #58a6ff; }
		.container { max-width: 1200px; margin: 0 auto; }
		.health { background: #161b22; padding: 10px; border: 1px solid #30363d; }
		table { border-collapse: collapse; width: 100%; margin-top: 10px; }
		tr, td, th { border: 1px solid #30363d; padding: 8px; text-align: left; }
		th { background: #0d1117; }
	</style>
</head>
<body>
	<div class="container">
		<h1>⚡ Sherlock - Bitcoin Chain Analysis</h1>
		<p>Interactive visualization of chain analysis results.</p>
		
		<h2>API Status</h2>
		<div class="health">
			<p>✅ Server is running and ready</p>
			<p>Available endpoints:</p>
			<ul>
				<li><code>GET /api/health</code> - Health check</li>
				<li><code>GET /api/blocks</code> - List blocks</li>
				<li><code>GET /api/block/{name}</code> - Get block analysis</li>
			</ul>
		</div>

		<h2>Block Analysis Results</h2>
		<div id="blocks"></div>
	</div>
	<script>
		async function loadBlocks() {
			const res = await fetch('/api/blocks');
			const data = await res.json();
			const container = document.getElementById('blocks');
			
			if (data.blocks && data.blocks.length > 0) {
				let html = '<table><tr><th>Block File</th><th></th></tr>';
				for (const block of data.blocks) {
					html += '<tr><td>' + block + '</td><td><a href="javascript:void(0)" onclick="loadBlock(\'' + block + '\')">View</a></td></tr>';
				}
				html += '</table>';
				container.innerHTML = html;
			} else {
				container.innerHTML = '<p>No blocks analyzed yet.</p>';
			}
		}
		
		function loadBlock(name) {
			window.location.href = '/block.html?block=' + name;
		}
		
		loadBlocks();
	</script>
</body>
</html>`))
	}
}

func main() {
	var port int
	flag.IntVar(&port, "port", 3000, "port to listen on")
	flag.Parse()

	// Check for PORT environment variable
	if portEnv := os.Getenv("PORT"); portEnv != "" {
		if p, err := strconv.Atoi(portEnv); err == nil {
			port = p
		}
	}

	server := NewServer(port)
	log.Fatal(server.Start())
}
