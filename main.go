package main

import (
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/smtp"
	"os"
	"strings"
	"time"
)

type ConnectionType string

const (
	ConnPlain    ConnectionType = "plain"    // Plain SMTP (no encryption)
	ConnSTARTTLS ConnectionType = "starttls" // STARTTLS (upgrade to TLS)
	ConnTLS      ConnectionType = "tls"      // Direct TLS/SSL (SMTPS)
)

type AuthType string

const (
	AuthPlain AuthType = "plain" // AUTH PLAIN
	AuthLogin AuthType = "login" // AUTH LOGIN
)

type Config struct {
	SMTPServer     string
	SMTPPort       string
	FromAddr       string
	ToAddrs        []string
	CcAddrs        []string
	BccAddrs       []string
	Username       string
	Password       string
	ConnectionType ConnectionType
	AuthType       AuthType
	Subject        string
	Body           string
	LogFile        string
}

// loginAuth implements AUTH LOGIN authentication
type loginAuth struct {
	username, password string
}

func LoginAuth(username, password string) smtp.Auth {
	return &loginAuth{username, password}
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", []byte{}, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		switch string(fromServer) {
		case "Username:", "User Name\x00":
			return []byte(a.username), nil
		case "Password:", "Password\x00":
			return []byte(a.password), nil
		default:
			// Handle base64 encoded prompts
			decoded, err := base64.StdEncoding.DecodeString(string(fromServer))
			if err == nil {
				decodedStr := strings.ToLower(string(decoded))
				if strings.Contains(decodedStr, "user") {
					return []byte(a.username), nil
				}
				if strings.Contains(decodedStr, "pass") {
					return []byte(a.password), nil
				}
			}
			return nil, fmt.Errorf("unexpected server challenge: %s", string(fromServer))
		}
	}
	return nil, nil
}

type Logger struct {
	logger *log.Logger
}

func NewLogger(logFile string) (*Logger, error) {
	var writers []io.Writer
	writers = append(writers, os.Stdout)

	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		writers = append(writers, f)
	}

	multiWriter := io.MultiWriter(writers...)
	logger := log.New(multiWriter, "", log.LstdFlags)

	return &Logger{logger: logger}, nil
}

func (l *Logger) Info(format string, v ...interface{}) {
	l.logger.Printf("[INFO] "+format, v...)
}

func (l *Logger) Error(format string, v ...interface{}) {
	l.logger.Printf("[ERROR] "+format, v...)
}

func (l *Logger) Success(format string, v ...interface{}) {
	l.logger.Printf("[SUCCESS] "+format, v...)
}

func getAuth(config *Config) smtp.Auth {
	if config.AuthType == AuthLogin {
		return LoginAuth(config.Username, config.Password)
	}
	return smtp.PlainAuth("", config.Username, config.Password, config.SMTPServer)
}

func sendEmail(config *Config, logger *Logger) error {
	logger.Info("Starting email send process")
	logger.Info("SMTP Server: %s:%s", config.SMTPServer, config.SMTPPort)
	logger.Info("From: %s", config.FromAddr)
	logger.Info("To: %s", strings.Join(config.ToAddrs, ", "))
	if len(config.CcAddrs) > 0 {
		logger.Info("Cc: %s", strings.Join(config.CcAddrs, ", "))
	}
	if len(config.BccAddrs) > 0 {
		logger.Info("Bcc: %s", strings.Join(config.BccAddrs, ", "))
	}
	logger.Info("Connection Type: %s", config.ConnectionType)

	// Check if authentication is configured
	if config.Username != "" && config.Password != "" {
		logger.Info("Authentication: Enabled (Username: %s, Type: %s)", config.Username, config.AuthType)
	} else {
		logger.Info("Authentication: Disabled (no credentials provided)")
	}

	// Prepare email message headers
	var msgBuilder strings.Builder
	msgBuilder.WriteString(fmt.Sprintf("From: %s\r\n", config.FromAddr))
	msgBuilder.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(config.ToAddrs, ", ")))

	if len(config.CcAddrs) > 0 {
		msgBuilder.WriteString(fmt.Sprintf("Cc: %s\r\n", strings.Join(config.CcAddrs, ", ")))
	}
	// Note: BCC addresses are NOT included in headers (that's the point of BCC)

	msgBuilder.WriteString(fmt.Sprintf("Subject: %s\r\n", config.Subject))
	msgBuilder.WriteString("\r\n")
	msgBuilder.WriteString(config.Body)
	msgBuilder.WriteString("\r\n")

	msg := []byte(msgBuilder.String())

	serverAddr := config.SMTPServer + ":" + config.SMTPPort

	switch config.ConnectionType {
	case ConnPlain:
		return sendEmailPlain(serverAddr, config, msg, logger)
	case ConnSTARTTLS:
		return sendEmailSTARTTLS(serverAddr, config, msg, logger)
	case ConnTLS:
		return sendEmailTLS(serverAddr, config, msg, logger)
	default:
		return fmt.Errorf("unsupported connection type: %s", config.ConnectionType)
	}
}

func sendEmailPlain(serverAddr string, config *Config, msg []byte, logger *Logger) error {
	logger.Info("Connecting to SMTP server (plain connection)...")

	// Connect to SMTP server
	client, err := smtp.Dial(serverAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	defer client.Close()
	logger.Info("Connected to SMTP server")

	// Authenticate only if credentials are provided
	if config.Username != "" && config.Password != "" {
		logger.Info("Attempting authentication with username: %s (method: %s)", config.Username, config.AuthType)
		auth := getAuth(config)
		if err = client.Auth(auth); err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
		logger.Info("Authentication successful")
	} else {
		logger.Info("Skipping authentication (no credentials provided)")
	}

	// Set sender
	if err = client.Mail(config.FromAddr); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}
	logger.Info("Sender set: %s", config.FromAddr)

	// Set all recipients (To, Cc, and Bcc)
	allRecipients := append([]string{}, config.ToAddrs...)
	allRecipients = append(allRecipients, config.CcAddrs...)
	allRecipients = append(allRecipients, config.BccAddrs...)

	for _, addr := range allRecipients {
		if err = client.Rcpt(addr); err != nil {
			return fmt.Errorf("failed to set recipient %s: %w", addr, err)
		}
		logger.Info("Recipient added: %s", addr)
	}

	// Send email body
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to initialize data transfer: %w", err)
	}

	_, err = w.Write(msg)
	if err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	err = w.Close()
	if err != nil {
		return fmt.Errorf("failed to close data writer: %w", err)
	}
	logger.Info("Email data sent successfully")

	// Quit
	err = client.Quit()
	if err != nil {
		return fmt.Errorf("failed to close connection: %w", err)
	}

	return nil
}

func sendEmailSTARTTLS(serverAddr string, config *Config, msg []byte, logger *Logger) error {
	logger.Info("Connecting to SMTP server (STARTTLS connection)...")

	// Connect to SMTP server (plain first)
	client, err := smtp.Dial(serverAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	defer client.Close()
	logger.Info("Connected to SMTP server")

	// Upgrade to TLS using STARTTLS
	tlsConfig := &tls.Config{
		ServerName: config.SMTPServer,
	}

	if err = client.StartTLS(tlsConfig); err != nil {
		return fmt.Errorf("failed to start TLS: %w", err)
	}
	logger.Info("TLS connection established via STARTTLS")

	// Authenticate only if credentials are provided
	if config.Username != "" && config.Password != "" {
		logger.Info("Attempting authentication with username: %s (method: %s)", config.Username, config.AuthType)
		auth := getAuth(config)
		if err = client.Auth(auth); err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
		logger.Info("Authentication successful")
	} else {
		logger.Info("Skipping authentication (no credentials provided)")
	}

	// Set sender
	if err = client.Mail(config.FromAddr); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}
	logger.Info("Sender set: %s", config.FromAddr)

	// Set all recipients (To, Cc, and Bcc)
	allRecipients := append([]string{}, config.ToAddrs...)
	allRecipients = append(allRecipients, config.CcAddrs...)
	allRecipients = append(allRecipients, config.BccAddrs...)

	for _, addr := range allRecipients {
		if err = client.Rcpt(addr); err != nil {
			return fmt.Errorf("failed to set recipient %s: %w", addr, err)
		}
		logger.Info("Recipient added: %s", addr)
	}

	// Send email body
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to initialize data transfer: %w", err)
	}

	_, err = w.Write(msg)
	if err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	err = w.Close()
	if err != nil {
		return fmt.Errorf("failed to close data writer: %w", err)
	}
	logger.Info("Email data sent successfully")

	// Quit
	err = client.Quit()
	if err != nil {
		return fmt.Errorf("failed to close connection: %w", err)
	}

	return nil
}

func sendEmailTLS(serverAddr string, config *Config, msg []byte, logger *Logger) error {
	logger.Info("Connecting to SMTP server (direct TLS/SMTPS connection)...")

	// TLS configuration
	tlsConfig := &tls.Config{
		ServerName: config.SMTPServer,
	}

	// Connect with TLS directly (SMTPS)
	conn, err := tls.Dial("tcp", serverAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to establish TLS connection: %w", err)
	}
	defer conn.Close()
	logger.Info("TLS connection established")

	// Create SMTP client
	client, err := smtp.NewClient(conn, config.SMTPServer)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer client.Close()
	logger.Info("Connected to SMTP server")

	// Authenticate only if credentials are provided
	if config.Username != "" && config.Password != "" {
		logger.Info("Attempting authentication with username: %s (method: %s)", config.Username, config.AuthType)
		auth := getAuth(config)
		if err = client.Auth(auth); err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
		logger.Info("Authentication successful")
	} else {
		logger.Info("Skipping authentication (no credentials provided)")
	}

	// Set sender
	if err = client.Mail(config.FromAddr); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}
	logger.Info("Sender set: %s", config.FromAddr)

	// Set all recipients (To, Cc, and Bcc)
	allRecipients := append([]string{}, config.ToAddrs...)
	allRecipients = append(allRecipients, config.CcAddrs...)
	allRecipients = append(allRecipients, config.BccAddrs...)

	for _, addr := range allRecipients {
		if err = client.Rcpt(addr); err != nil {
			return fmt.Errorf("failed to set recipient %s: %w", addr, err)
		}
		logger.Info("Recipient added: %s", addr)
	}

	// Send email body
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to initialize data transfer: %w", err)
	}

	_, err = w.Write(msg)
	if err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	err = w.Close()
	if err != nil {
		return fmt.Errorf("failed to close data writer: %w", err)
	}
	logger.Info("Email data sent successfully")

	// Quit
	err = client.Quit()
	if err != nil {
		return fmt.Errorf("failed to close connection: %w", err)
	}

	return nil
}

func parseEmailList(emailStr string) []string {
	if emailStr == "" {
		return []string{}
	}
	emails := strings.Split(emailStr, ",")
	result := make([]string, 0, len(emails))
	for _, addr := range emails {
		trimmed := strings.TrimSpace(addr)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func main() {
	// Define command line flags
	smtpServer := flag.String("server", "", "SMTP server address (required)")
	smtpPort := flag.String("port", "25", "SMTP server port (default: 25)")
	fromAddr := flag.String("from", "", "Sender email address (required)")
	toAddrs := flag.String("to", "", "Recipient email address(es), comma-separated (required)")
	ccAddrs := flag.String("cc", "", "Cc email address(es), comma-separated (optional)")
	bccAddrs := flag.String("bcc", "", "Bcc email address(es), comma-separated (optional)")
	username := flag.String("user", "", "SMTP username for authentication (optional)")
	password := flag.String("password", "", "SMTP password for authentication (optional)")
	connType := flag.String("conn", "plain", "Connection type: plain, starttls, or tls (default: plain)")
	authType := flag.String("auth", "plain", "Authentication type: plain or login (default: plain)")
	subject := flag.String("subject", "Test Email", "Email subject")
	body := flag.String("body", "This is a test email from BHPetrol Email Testing Tool.", "Email body")
	logFile := flag.String("log", "", "Log file path (optional, logs to stdout if not specified)")

	flag.Parse()

	// Validate required flags
	if *smtpServer == "" || *fromAddr == "" || *toAddrs == "" {
		fmt.Println("Error: Required flags missing")
		fmt.Println("\nRequired flags:")
		fmt.Println("  -server   SMTP server address")
		fmt.Println("  -from     Sender email address")
		fmt.Println("  -to       Recipient email address(es), comma-separated")
		fmt.Println("\nOptional flags:")
		fmt.Println("  -port     SMTP server port (default: 25)")
		fmt.Println("  -cc       Cc email address(es), comma-separated")
		fmt.Println("  -bcc      Bcc email address(es), comma-separated")
		fmt.Println("  -user     SMTP username (for authenticated servers)")
		fmt.Println("  -password SMTP password (for authenticated servers)")
		fmt.Println("  -conn     Connection type: plain, starttls, or tls (default: plain)")
		fmt.Println("            plain    - Plain SMTP without encryption (port 25)")
		fmt.Println("            starttls - Start with plain, upgrade to TLS (port 587)")
		fmt.Println("            tls      - Direct TLS connection/SMTPS (port 465)")
		fmt.Println("  -auth     Authentication type: plain or login (default: plain)")
		fmt.Println("            plain    - AUTH PLAIN")
		fmt.Println("            login    - AUTH LOGIN")
		fmt.Println("  -subject  Email subject")
		fmt.Println("  -body     Email body")
		fmt.Println("  -log      Log file path")
		os.Exit(1)
	}

	// Validate connection type
	var connectionType ConnectionType
	switch strings.ToLower(*connType) {
	case "plain":
		connectionType = ConnPlain
	case "starttls":
		connectionType = ConnSTARTTLS
	case "tls":
		connectionType = ConnTLS
	default:
		fmt.Printf("Error: Invalid connection type '%s'. Must be: plain, starttls, or tls\n", *connType)
		os.Exit(1)
	}

	// Validate authentication type
	var authenticationType AuthType
	switch strings.ToLower(*authType) {
	case "plain":
		authenticationType = AuthPlain
	case "login":
		authenticationType = AuthLogin
	default:
		fmt.Printf("Error: Invalid authentication type '%s'. Must be: plain or login\n", *authType)
		os.Exit(1)
	}

	// Parse recipient addresses
	recipients := parseEmailList(*toAddrs)
	ccRecipients := parseEmailList(*ccAddrs)
	bccRecipients := parseEmailList(*bccAddrs)

	// Create configuration
	config := &Config{
		SMTPServer:     *smtpServer,
		SMTPPort:       *smtpPort,
		FromAddr:       *fromAddr,
		ToAddrs:        recipients,
		CcAddrs:        ccRecipients,
		BccAddrs:       bccRecipients,
		Username:       *username,
		Password:       *password,
		ConnectionType: connectionType,
		AuthType:       authenticationType,
		Subject:        *subject,
		Body:           *body,
		LogFile:        *logFile,
	}

	// Initialize logger
	logger, err := NewLogger(*logFile)
	if err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	logger.Info("=== BHPetrol Email Testing Tool ===")
	logger.Info("Starting at: %s", time.Now().Format(time.RFC3339))

	// Send email
	if err := sendEmail(config, logger); err != nil {
		logger.Error("Failed to send email: %v", err)
		os.Exit(1)
	}

	logger.Success("Email sent successfully!")
	logger.Info("Completed at: %s", time.Now().Format(time.RFC3339))
}
