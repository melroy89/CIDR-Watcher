package main

import (
	"bufio"
	"database/sql"
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
	influx "github.com/influxdata/influxdb1-client"
	"github.com/joho/godotenv"
	mail "github.com/wneessen/go-mail"
)

const (
	defaultWatchFile      = "./watch_list.txt"
	defaultPollInterval   = 30
	defaultReloadInterval = 1500
	defaultInfluxLimit    = 5000
	influxMeasurement     = "nginx_access_log"
	auditStateRowID       = 1
	defaultMailFromName   = "CIDR Watcher"
	defaultMailFromAddr   = "no-reply@melroy.org"
	defaultMailThreshold  = int64(10)
)

type Config struct {
	InfluxUnixSock string
	InfluxDB       string
	InfluxUser     string
	InfluxPass     string
	MySQLDSN       string
	WatchFile      string
	PollInterval   time.Duration
	ReloadInterval time.Duration
	InfluxLimit    int
	MailFromName   string
	MailFromAddr   string
	MailTo         string
	MailThreshold  int64
}

type Watcher struct {
	mu            sync.RWMutex
	running       bool
	cfg           Config
	influxCli     *influx.Client
	sqlDB         *sql.DB
	cidrs         []*net.IPNet
	lastProcessed int64 // unix nanoseconds
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
	ticker := time.NewTicker(w.cfg.PollInterval)
	defer ticker.Stop()
	w.pollOnce()
	for {
		err := w.pollOnce()
		if err != nil {
			log.Printf("poll error: %v", err)
		}
		<-ticker.C
	}
}

func (w *Watcher) Start() error {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return nil
	}
	w.running = true
	w.mu.Unlock()

	// Start loop
	go w.loop()
	return nil
}

func (w *Watcher) loop() {
	ticker := time.NewTicker(w.cfg.PollInterval)
	defer ticker.Stop()
	w.pollOnce()
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

	limit := defaultInfluxLimit
	if lv := os.Getenv("INFLUX_QUERY_LIMIT"); lv != "" {
		if vi, err := strconv.Atoi(lv); err == nil {
			limit = vi
		} else {
			log.Printf("invalid INFLUX_QUERY_LIMIT %q, using default %d: %v", lv, defaultInfluxLimit, err)
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
	influxDB := strings.TrimSpace(os.Getenv("INFLUX_DB"))
	if influxDB == "" {
		influxDB = "telegraf"
	}
	influxUser := strings.TrimSpace(os.Getenv("INFLUX_USER"))
	influxPass := strings.TrimSpace(os.Getenv("INFLUX_PASS"))
	influxUnixSock := strings.TrimSpace(os.Getenv("INFLUX_UNIX_SOCKET"))
	if influxUnixSock == "" {
		influxUnixSock = "/var/run/influxdb/influxdb.sock"
	}
	// mysql
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
		InfluxUnixSock: influxUnixSock,
		InfluxDB:       influxDB,
		InfluxUser:     influxUser,
		InfluxPass:     influxPass,
		MySQLDSN:       mysqlDSN,
		WatchFile:      watchFile,
		PollInterval:   time.Duration(poll) * time.Second,
		ReloadInterval: time.Duration(reload) * time.Second,
		InfluxLimit:    limit,
		MailFromName:   mailFromName,
		MailFromAddr:   mailFromAddr,
		MailTo:         mailTo,
		MailThreshold:  mailThreshold,
	}
}

func (w *Watcher) init() error {
	// influx client (use socket file)
	cfg := influx.Config{
		Username:   w.cfg.InfluxUser,
		Password:   w.cfg.InfluxPass,
		UnixSocket: w.cfg.InfluxUnixSock,
		Timeout:    10 * time.Second,
		UserAgent:  "CIDRWatcher",
	}

	c, err := influx.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("create influx client: %w", err)
	}
	w.influxCli = c

	// mysql
	db, err := sql.Open("mysql", w.cfg.MySQLDSN)
	if err != nil {
		return fmt.Errorf("open mysql: %w", err)
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

func (w *Watcher) loadState() error {
	// Use transaction for safety.
	tx, err := w.sqlDB.Begin()
	if err != nil {
		return err
	}

	// try select
	var last sql.NullInt64
	err = tx.QueryRow("SELECT last_processed FROM audit_state WHERE id = ?", auditStateRowID).Scan(&last)
	if err != nil {
		if err == sql.ErrNoRows {
			_, err = tx.Exec("INSERT INTO audit_state (id, last_processed) VALUES (?, ?)", auditStateRowID, 0)
			if err != nil {
				_ = tx.Rollback()
				return err
			}
			w.lastProcessed = 0
		} else {
			_ = tx.Rollback()
			return err
		}
	} else {
		if last.Valid {
			w.lastProcessed = last.Int64
		} else {
			w.lastProcessed = 0
		}
	}

	if err := tx.Commit(); err != nil {
		// commit failed; attempt rollback and return the commit error
		_ = tx.Rollback()
		return err
	}
	log.Printf("last_processed loaded: %d (unix-ns)", w.lastProcessed)
	return nil
}

func (w *Watcher) pollOnce() error {
	// build query
	var q string
	if w.lastProcessed == 0 {
		q = fmt.Sprintf("SELECT time, remote_ip FROM %s ORDER BY time ASC LIMIT %d", influxMeasurement, w.cfg.InfluxLimit)
	} else {
		// convert lastProcessed (ns) -> RFC3339Nano
		time := time.Unix(0, w.lastProcessed).UTC().Format(time.RFC3339Nano)
		q = fmt.Sprintf("SELECT time, remote_ip FROM %s WHERE time > '%s' ORDER BY time ASC LIMIT %d", influxMeasurement, time, w.cfg.InfluxLimit)
	}

	resp, err := queryInflux(w.influxCli, w.cfg.InfluxDB, q)
	if err != nil {
		return fmt.Errorf("influx query: %w", err)
	}

	if len(resp) == 0 {
		// nothing new
		return nil
	}

	// process rows
	var maxSeen int64 = w.lastProcessed
	var processed int
	for _, res := range resp {
		if res.Series == nil {
			// no data
			continue
		}
		for _, series := range res.Series {
			// find indices for time and remote_ip
			timeIdx := -1
			remoteIpIdx := -1
			userAgentIdx := -1
			bodySentBytesIdx := -1
			domainnameIdx := -1
			httpMethodIdx := -1
			referrerIdx := -1
			responseCodeIdx := -1
			urlIdx := -1
			for i, col := range series.Columns {
				if col == "time" {
					timeIdx = i
				}
				if col == "agent" {
					userAgentIdx = i
				}
				if col == "body_sent_bytes" {
					bodySentBytesIdx = i
				}
				if col == "domainname" {
					domainnameIdx = i
				}
				if col == "http_method" {
					httpMethodIdx = i
				}
				if col == "referrer" {
					referrerIdx = i
				}
				if col == "remote_ip" {
					remoteIpIdx = i
				}
				if col == "response_code" {
					responseCodeIdx = i
				}
				if col == "url" {
					urlIdx = i
				}
			}

			if timeIdx == -1 {
				log.Printf("series missing time column, skipping")
				continue
			}
			if remoteIpIdx == -1 {
				// nothing to check
				continue
			}

			for _, row := range series.Values {
				processed++
				// time is usually string in RFC3339
				timeStr, ok := row[timeIdx].(string)
				if !ok {
					continue
				}
				t, err := time.Parse(time.RFC3339Nano, timeStr)
				if err != nil {
					// try fallback to parse without nano
					t2, err2 := time.Parse(time.RFC3339, timeStr)
					if err2 != nil {
						log.Printf("failed to parse time '%v': %v / %v", timeStr, err, err2)
						continue
					}
					t = t2
				}
				ns := t.UnixNano()
				if ns > maxSeen {
					maxSeen = ns
				}

				// remote_ip column may be string or nil
				var remoteIp string
				var userAgent string
				var bodySentBytes int64
				var domainname string
				var httpMethod string
				var referrer string
				var responseCode int
				var url string
				if row[remoteIpIdx] != nil {
					remoteIp, _ = row[remoteIpIdx].(string)
					userAgent, _ = row[userAgentIdx+1].(string)
					bodySentBytes, _ = row[bodySentBytesIdx+1].(int64)
					domainname, _ = row[domainnameIdx+1].(string)
					httpMethod, _ = row[httpMethodIdx+1].(string)
					referrer, _ = row[referrerIdx+1].(string)
					responseCode, _ = row[responseCodeIdx+1].(int)
					url, _ = row[urlIdx+1].(string)
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
		}
	}

	// update last processed if changed
	if maxSeen > w.lastProcessed {
		if err := w.updateState(maxSeen); err != nil {
			return fmt.Errorf("update state: %w", err)
		}
		w.lastProcessed = maxSeen
	}
	if processed > 0 {
		log.Printf("processed %d rows, last_processed now %d", processed, w.lastProcessed)
	}
	return nil
}

func queryInflux(c *influx.Client, db, cmd string) ([]influx.Result, error) {
	q := influx.Query{
		Command:  cmd,
		Database: db,
	}
	resp, err := c.Query(q)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("nil response from influx")
	}
	if resp.Error() != nil {
		return nil, resp.Error()
	}
	return resp.Results, nil
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
func (w *Watcher) upsertIP(remoteIp string, userAgent string, bodySentBytes int64, domainname string, httpMethod string, referrer string, responseCode int, url string) error {
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
			_, err = tx.Exec("INSERT INTO audit_ips (ip, hits, last_user_agent, last_body_sent_bytes, last_domainname, last_http_method, last_referrer, last_response_code, last_url) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?)", remoteIp, userAgent, bodySentBytes, domainname, httpMethod, referrer, responseCode, url)
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
	_, err = tx.Exec("UPDATE audit_ips SET hits = ?, last_user_agent = ?, last_body_sent_bytes = ?, last_domainname = ?, last_http_method = ?, last_referrer = ?, last_response_code = ?, last_url = ? WHERE ip = ?", newHits, userAgent, bodySentBytes, domainname, httpMethod, referrer, responseCode, url, remoteIp)
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
		if err := w.sendNotification(remoteIp, newHits); err != nil {
			log.Printf("failed to send notification for %s: %v", remoteIp, err)
		} else {
			// log success
			log.Printf("sent notification: %s reached %d hits", remoteIp, newHits)
		}
	}
	return nil
}

func (w *Watcher) sendNotification(ip string, hits int64) error {
	// If no recipient is configured then the notification is optional; do nothing and return success.
	if strings.TrimSpace(w.cfg.MailTo) == "" {
		log.Printf("notification suppressed for %s (%d hits): no MAIL_TO configured", ip, hits)
		return nil
	}
	m := mail.NewMsg()
	body := fmt.Sprintf("IP %s reached %d hits", ip, hits)
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

func (w *Watcher) updateState(ns int64) error {
	_, err := w.sqlDB.Exec("UPDATE audit_state SET last_processed = ? WHERE id = ?", ns, auditStateRowID)
	return err
}
