package main

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	client "github.com/influxdata/influxdb1-client/v2"
	"github.com/joho/godotenv"
	mail "github.com/wneessen/go-mail"
)

const (
	defaultWatchFile         = "./watch_list.txt"
	defaultPollInterval      = 30
	defaultReloadInterval    = 3000
	defaultInfluxLimit       = 5000
	defaultInfluxAddr        = "http://localhost:8086"
	defaultInfluxMeasurement = "nginx_access_log"
	defaultInfluxDB          = "telegraf"
	auditStateRowID          = 1
	defaultMailFromName      = "CIDR Watcher"
	defaultMailFromAddr      = "no-reply@melroy.org"
	defaultMailThreshold     = int64(10)
	influxPrecision          = "ns"
)

type Config struct {
	InfluxAddr        string
	InfluxDB          string
	InfluxMeasurement string
	InfluxUser        string
	InfluxPass        string
	InfluxLimit       int
	MySQLDSN          string
	WatchFile         string
	PollInterval      time.Duration
	ReloadInterval    time.Duration
	MailFromName      string
	MailFromAddr      string
	MailTo            string
	MailThreshold     int64
}

type Watcher struct {
	mu            sync.RWMutex
	cfg           Config
	influxClient  client.Client
	sqlDB         *sql.DB
	cidrs         []*net.IPNet
	lastTimestamp int64 // unix nanoseconds
}

func main() {
	// Allow flags for quick testing
	var (
		flPoll = flag.Int("poll", 0, "poll interval seconds (overrides POLL_INTERVAL_SECONDS env)")
	)
	flag.Parse()

	// Load .env if present to allow local env var overrides
	if err := godotenv.Load(); err != nil {
		// Not fatal; log and continue. If the file isn't present, environment variables may still be set.
		log.Printf("warning: could not load .env file: %v", err)
	}

	cfg := loadConfig()
	if *flPoll > 0 {
		cfg.PollInterval = time.Duration(*flPoll) * time.Second
	}

	w := &Watcher{cfg: cfg}
	if err := w.init(); err != nil {
		log.Fatalf("init: %v", err)
	}

	// start watchlist reload ticker
	go func() {
		t := time.NewTicker(w.cfg.ReloadInterval)
		defer t.Stop()
		for range t.C {
			if err := w.loadCIDRs(); err != nil {
				log.Printf("watchlist reload error: %v", err)
			}
		}
	}()

	// main loop
	w.loop()
}

func (w *Watcher) loop() {
	ticker := time.NewTicker(w.cfg.PollInterval)
	defer ticker.Stop()
	for {
		err := w.pollOnce()
		if err != nil {
			log.Printf("poll error: %v", err)
		}
		<-ticker.C
	}
}

func loadConfig() Config {
	// parse integer env vars manually and fall back to defaults if missing or invalid
	poll := defaultPollInterval
	if pv := os.Getenv("POLL_INTERVAL_SECONDS"); pv != "" {
		if vi, err := strconv.Atoi(pv); err == nil {
			poll = vi
		} else {
			log.Printf("invalid POLL_INTERVAL_SECONDS %q, using default %d: %v", pv, defaultPollInterval, err)
		}
	}

	reload := defaultReloadInterval
	if rv := os.Getenv("WATCHLIST_RELOAD_SECONDS"); rv != "" {
		if vi, err := strconv.Atoi(rv); err == nil {
			reload = vi
		} else {
			log.Printf("invalid WATCHLIST_RELOAD_SECONDS %q, using default %d: %v", rv, defaultReloadInterval, err)
		}
	}

	// mail config
	mailFromName := os.Getenv("MAIL_FROM_NAME")
	if mailFromName == "" {
		mailFromName = defaultMailFromName
	}
	mailFromAddr := os.Getenv("MAIL_FROM_ADDR")
	if mailFromAddr == "" {
		mailFromAddr = defaultMailFromAddr
	}
	mailTo := os.Getenv("MAIL_TO")
	mailThreshold := defaultMailThreshold
	if mt := os.Getenv("ALERT_HIT_THRESHOLD"); mt != "" {
		if number, err := strconv.ParseInt(mt, 10, 64); err == nil {
			mailThreshold = number
		} else {
			log.Printf("invalid ALERT_HIT_THRESHOLD %q, using default %d: %v", mt, defaultMailThreshold, err)
		}
	}
	// influx
	limit := defaultInfluxLimit
	if lv := os.Getenv("INFLUX_QUERY_LIMIT"); lv != "" {
		if vi, err := strconv.Atoi(lv); err == nil {
			limit = vi
		} else {
			log.Printf("invalid INFLUX_QUERY_LIMIT %q, using default %d: %v", lv, defaultInfluxLimit, err)
		}
	}

	influxMeasurement := strings.TrimSpace(os.Getenv("INFLUX_MEASUREMENT"))
	if influxMeasurement == "" {
		influxMeasurement = defaultInfluxMeasurement
	}

	influxDB := strings.TrimSpace(os.Getenv("INFLUX_DB"))
	if influxDB == "" {
		influxDB = defaultInfluxDB
	}
	influxUser := strings.TrimSpace(os.Getenv("INFLUX_USER"))
	influxPass := strings.TrimSpace(os.Getenv("INFLUX_PASS"))
	influxAddr := strings.TrimSpace(os.Getenv("INFLUX_ADDR"))
	if influxAddr == "" {
		influxAddr = defaultInfluxAddr
	}
	// MariaDB
	mysqlDSN := os.Getenv("MYSQL_DSN")
	// Default to unix socket at /var/run/mysqld/mysqld.sock when MYSQL_DSN not provided
	if mysqlDSN == "" {
		mysqlDSN = "root:password@unix(/var/run/mysqld/mysqld.sock)/audit?parseTime=true"
	}
	watchFile := strings.TrimSpace(os.Getenv("WATCH_LIST_FILE"))
	if watchFile == "" {
		watchFile = defaultWatchFile
	}

	return Config{
		InfluxAddr:        influxAddr,
		InfluxDB:          influxDB,
		InfluxMeasurement: influxMeasurement,
		InfluxUser:        influxUser,
		InfluxPass:        influxPass,
		InfluxLimit:       limit,
		MySQLDSN:          mysqlDSN,
		WatchFile:         watchFile,
		PollInterval:      time.Duration(poll) * time.Second,
		ReloadInterval:    time.Duration(reload) * time.Second,
		MailFromName:      mailFromName,
		MailFromAddr:      mailFromAddr,
		MailTo:            mailTo,
		MailThreshold:     mailThreshold,
	}
}

func (w *Watcher) init() error {
	// influxdbv1
	con, err := client.NewHTTPClient(client.HTTPConfig{
		Addr:      w.cfg.InfluxAddr,
		Username:  w.cfg.InfluxUser,
		Password:  w.cfg.InfluxPass,
		Timeout:   10 * time.Second,
		UserAgent: "CIDRWatcher",
	})
	if err != nil {
		log.Fatalln("Error creating InfluxDB Client: %w", err.Error())
	}
	defer con.Close()
	w.influxClient = con

	// mysql
	db, err := sql.Open("mysql", w.cfg.MySQLDSN)
	if err != nil {
		log.Fatalln("Unable to create MySQL client: %w", err)
		return err
	}
	db.SetMaxOpenConns(10)
	db.SetConnMaxLifetime(5 * time.Minute)
	w.sqlDB = db

	// load last processed from DB (or create row)
	if err := w.loadState(); err != nil {
		return fmt.Errorf("load state: %w", err)
	}

	// load CIDRs initially
	if err := w.loadCIDRs(); err != nil {
		log.Printf("warning: failed to load watchlist at startup: %v", err)
		return err
	}

	return nil
}

func (w *Watcher) loadCIDRs() error {
	path := w.cfg.WatchFile
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var list []*net.IPNet
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// support both plain IPs and CIDRs
		if !strings.Contains(line, "/") {
			// treat single IP as /32 or /128
			if strings.Contains(line, ":") {
				// ipv6
				line = line + "/128"
			} else {
				// ipv4
				line = line + "/32"
			}
		}
		_, ipnet, err := net.ParseCIDR(line)
		if err != nil {
			log.Printf("invalid cidr '%s' in watchlist: %v", scanner.Text(), err)
			continue
		}
		list = append(list, ipnet)
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	w.mu.Lock()
	w.cidrs = list
	w.mu.Unlock()
	log.Printf("loaded %d CIDRs/IPs from %s", len(list), path)
	return nil
}

func (w *Watcher) pollOnce() error {
	// Be sure to get the latest last_processed_timestamp directly from MariaDB
	// Which will update w.lastTimestamp...
	w.retrieveLastTimestamp()

	// build query
	var q string
	if w.lastTimestamp == 0 {
		q = fmt.Sprintf("SELECT time, remote_ip, agent, body_sent_bytes, domainname, http_method, referrer, response_code, url FROM %s ORDER BY time DESC LIMIT %d", w.cfg.InfluxMeasurement, w.cfg.InfluxLimit)
	} else {
		q = fmt.Sprintf("SELECT time, remote_ip, agent, body_sent_bytes, domainname, http_method, referrer, response_code, url FROM %s WHERE time > %d ORDER BY time DESC LIMIT %d", w.cfg.InfluxMeasurement, w.lastTimestamp, w.cfg.InfluxLimit)
	}

	log.Printf("InfluxDB Query: %s", q)
	newQuery := client.NewQuery(q, w.cfg.InfluxDB, influxPrecision)
	resp, err := w.influxClient.Query(newQuery)
	if err != nil || resp.Error() != nil {
		return fmt.Errorf("influx query: %w", err)
	}

	if len(resp.Results) == 0 || resp.Results[0].Series == nil {
		// Nothing new
		return nil
	}

	series := resp.Results[0].Series[0]
	for rowIdx, row := range series.Values {
		var (
			timestamp     int64
			remoteIp      string
			userAgent     string
			bodySentBytes int64
			domainname    string
			httpMethod    string
			referrer      string
			responseCode  int64
			url           string
		)
		for i, colName := range series.Columns {
			if colName == "time" {
				// timeStamp will be used in the state table later
				timestamp, err = (row[i]).(json.Number).Int64()
				if err != nil {
					log.Println("Unable to parse time column from InfluxDB!?, skipping")
					continue
				}
				if rowIdx == 0 {
					// Retrieve the latest date, which is the first row
					w.lastTimestamp = timestamp
				}
			}
			if colName == "remote_ip" {
				if s, ok := row[i].(string); ok {
					remoteIp = s
				}
			}
			if colName == "agent" {
				if s, ok := row[i].(string); ok {
					userAgent = s
				}
			}
			if colName == "body_sent_bytes" {
				if n, ok := row[i].(json.Number); ok {
					bodySentBytes, _ = n.Int64()
				}
			}
			if colName == "domainname" {
				if s, ok := row[i].(string); ok {
					domainname = s
				}
			}
			if colName == "http_method" {
				if s, ok := row[i].(string); ok {
					httpMethod = s
				}
			}
			if colName == "referrer" {
				if s, ok := row[i].(string); ok {
					referrer = s
				}
			}
			if colName == "response_code" {
				if n, ok := row[i].(json.Number); ok {
					responseCode, _ = n.Int64()
				}
			}
			if colName == "url" {
				if s, ok := row[i].(string); ok {
					url = s
				}
			}
		}

		if remoteIp == "" {
			// No remote IP? That is weird, skip.
			log.Printf("row with empty remote_ip, skipping")
			continue
		}

		// check if IP matches watch list
		if w.ipMatchesWatchList(remoteIp) {
			if err := w.upsertIP(remoteIp, userAgent, bodySentBytes, domainname, httpMethod, referrer, responseCode, url); err != nil {
				log.Printf("upsert remote ip %s error: %v", remoteIp, err)
			}
		}
	}

	if err := w.updateState(); err != nil {
		return fmt.Errorf("failed to update state: %w", err)
	}
	return nil
}

func (w *Watcher) ipMatchesWatchList(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	for _, n := range w.cidrs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// upsertIP updates or inserts the remote IP in audit_ips table, increments hit count, and sends notification if threshold crossed.
func (w *Watcher) upsertIP(remoteIp string, userAgent string, bodySentBytes int64, domainname string, httpMethod string, referrer string, responseCode int64, url string) error {
	// perform a transaction to atomically update and capture new hit count
	tx, err := w.sqlDB.Begin()
	if err != nil {
		return err
	}

	var oldHits sql.NullInt64
	err = tx.QueryRow("SELECT hits FROM audit_ips WHERE ip = ? FOR UPDATE", remoteIp).Scan(&oldHits)
	if err != nil {
		if err == sql.ErrNoRows {
			// insert
			_, err = tx.Exec("INSERT INTO audit_ips (ip, hits, last_user_agent, last_body_sent_bytes, last_domainname, last_http_method, last_referrer, last_response_status_code, last_path) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?)", remoteIp, userAgent, bodySentBytes, domainname, httpMethod, referrer, responseCode, url)
			if err != nil {
				_ = tx.Rollback()
				return err
			}
			if err := tx.Commit(); err != nil {
				_ = tx.Rollback()
				return err
			}
			// hits == 1; no notification
			return nil
		}
		// query failed; rollback and return
		_ = tx.Rollback()
		return err
	}

	// increment
	newHits := oldHits.Int64 + 1
	_, err = tx.Exec("UPDATE audit_ips SET hits = ?, last_user_agent = ?, last_body_sent_bytes = ?, last_domainname = ?, last_http_method = ?, last_referrer = ?, last_response_status_code = ?, last_path = ? WHERE ip = ?", newHits, userAgent, bodySentBytes, domainname, httpMethod, referrer, responseCode, url, remoteIp)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		_ = tx.Rollback()
		return err
	}

	// if we just crossed the threshold, send notification
	if oldHits.Int64 < w.cfg.MailThreshold && newHits >= w.cfg.MailThreshold {
		if err := w.sendNotification(remoteIp, newHits, domainname, url, responseCode); err != nil {
			log.Printf("failed to send notification for %s: %v", remoteIp, err)
		} else {
			// log success
			log.Printf("sent notification: %s reached %d hits", remoteIp, newHits)
		}
	}
	return nil
}

func (w *Watcher) sendNotification(ip string, hits int64, domainname string, url string, responseCode int64) error {
	// If no recipient is configured then the notification is optional; do nothing and return success.
	if strings.TrimSpace(w.cfg.MailTo) == "" {
		log.Printf("notification suppressed for %s (%d hits): no MAIL_TO configured", ip, hits)
		return nil
	}
	m := mail.NewMsg()
	body := fmt.Sprintf("IP %s reached %d hits. With latest request URL: %s%s with status code: %d", ip, hits, domainname, url, responseCode)
	m.SetBodyString(mail.TypeTextPlain, body)
	if err := m.FromFormat(w.cfg.MailFromName, w.cfg.MailFromAddr); err != nil {
		return fmt.Errorf("set from: %w", err)
	}
	if err := m.To(w.cfg.MailTo); err != nil {
		return fmt.Errorf("set to: %w", err)
	}
	if err := m.WriteToSendmail(); err != nil {
		return fmt.Errorf("send: %w", err)
	}
	return nil
}

// Only used once during startup
func (w *Watcher) loadState() error {
	// Use transaction for safety.
	tx, err := w.sqlDB.Begin()
	if err != nil {
		return err
	}

	// try select
	var last sql.NullInt64
	err = tx.QueryRow("SELECT last_processed_timestamp FROM audit_state WHERE id = ?", auditStateRowID).Scan(&last)
	if err != nil {
		if err == sql.ErrNoRows {
			_, err = tx.Exec("INSERT INTO audit_state (id, last_processed_timestamp) VALUES (?, ?)", auditStateRowID, 0)
			if err != nil {
				_ = tx.Rollback()
				return err
			}
			w.lastTimestamp = 0
		} else {
			_ = tx.Rollback()
			return err
		}
	} else {
		if last.Valid {
			w.lastTimestamp = last.Int64
		} else {
			w.lastTimestamp = 0
		}
	}

	if err := tx.Commit(); err != nil {
		// commit failed; attempt rollback and return the commit error
		_ = tx.Rollback()
		return err
	}
	log.Printf("last_processed_timestamp loaded: %d (unix-ns)", w.lastTimestamp)
	return nil
}

func (w *Watcher) retrieveLastTimestamp() error {
	var last sql.NullInt64
	err := w.sqlDB.QueryRow("SELECT last_processed_timestamp FROM audit_state WHERE id = ?", auditStateRowID).Scan(&last)
	if err != nil {
		log.Printf("Unable to retrieve last_processed_timestamp: %v", err)
	} else {
		if last.Valid {
			w.lastTimestamp = last.Int64
		} else {
			w.lastTimestamp = 0
		}
	}
	return err
}

func (w *Watcher) updateState() error {
	_, err := w.sqlDB.Exec("UPDATE audit_state SET last_processed_timestamp = ? WHERE id = ?", w.lastTimestamp, auditStateRowID)
	return err
}
