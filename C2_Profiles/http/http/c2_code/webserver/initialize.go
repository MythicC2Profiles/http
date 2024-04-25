package webserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"time"

	mythicConfig "github.com/MythicMeta/MythicContainer/config"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/gin-gonic/gin"
)

func Initialize(configInstance instanceConfig) *gin.Engine {
	if mythicConfig.MythicConfig.DebugLevel == "warning" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}
	r := gin.New()
	gin.DisableConsoleColor()
	// Global middleware
	r.Use(InitializeGinLogger(configInstance))
	// Recovery middleware recovers from any panics and writes a 500 if there was one.
	r.Use(gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		if err, ok := recovered.(string); ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("error: %s", err)})
		}
		c.AbortWithStatus(http.StatusInternalServerError)
	}))
	r.RedirectFixedPath = true
	r.HandleMethodNotAllowed = true
	r.RemoveExtraSlash = true
	r.MaxMultipartMemory = 8 << 20 // 8 MB
	// set up the routes to use
	setRoutes(r, configInstance)
	return r
}

func StartServer(r *gin.Engine, configInstance instanceConfig) {
	logging.LogInfo("Starting webserver", "config", configInstance)
	if configInstance.UseSSL {
		if err := checkCerts(configInstance.CertPath, configInstance.KeyPath); err != nil {
			// certs don't exist, so generate them
			if err = generateCerts(configInstance); err != nil {
				logging.LogFatalError(err, "Failed to generate certs")
			}
		}
		if configInstance.BindIP != "" {
			go backgroundRunTLS(r, fmt.Sprintf("%s:%d", configInstance.BindIP, configInstance.Port), configInstance.CertPath, configInstance.KeyPath)
		} else {
			go backgroundRunTLS(r, fmt.Sprintf("%s:%d", "0.0.0.0", configInstance.Port), configInstance.CertPath, configInstance.KeyPath)
		}
	} else {
		if configInstance.BindIP != "" {
			go backgroundRun(r, fmt.Sprintf("%s:%d", configInstance.BindIP, configInstance.Port))
		} else {
			go backgroundRun(r, fmt.Sprintf("%s:%d", "0.0.0.0", configInstance.Port))
		}

	}
}

func backgroundRun(r *gin.Engine, address string) {
	if err := r.Run(address); err != nil {
		logging.LogFatalError(err, "Failed to run webserver")
	}
}
func backgroundRunTLS(r *gin.Engine, address string, certPath string, keyPath string) {
	if err := r.RunTLS(address, certPath, keyPath); err != nil {
		logging.LogFatalError(err, "Failed to run webserver")
	}
}

func InitializeGinLogger(configInstance instanceConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Start timer
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery
		//logging.LogDebug("got new request")
		// Process request
		c.Next()
		param := gin.LogFormatterParams{
			Request: c.Request,
			Keys:    c.Keys,
		}

		// Stop timer
		param.TimeStamp = time.Now()
		param.Latency = param.TimeStamp.Sub(start)

		param.ClientIP = c.ClientIP()
		param.Method = c.Request.Method
		param.StatusCode = c.Writer.Status()
		param.ErrorMessage = c.Errors.ByType(gin.ErrorTypePrivate).String()

		param.BodySize = c.Writer.Size()

		if raw != "" {
			path = path + "?" + raw
		}

		param.Path = path
		if configInstance.Debug {
			logging.LogInfo("WebServer Logging",
				"ClientIP", param.ClientIP,
				"method", param.Method,
				"path", param.Path,
				"protocol", param.Request.Proto,
				"statusCode", param.StatusCode,
				"latency", param.Latency,
				"error", param.ErrorMessage)
		}
		c.Next()
	}
}

func setRoutes(r *gin.Engine, configInstance instanceConfig) {
	// define generic get/post routes
	director := func(req *http.Request) {
		req.URL.Scheme = "http"
		req.URL.Host = fmt.Sprintf("%s:%d", mythicConfig.MythicConfig.MythicServerHost, mythicConfig.MythicConfig.MythicServerPort)
		req.Host = fmt.Sprintf("%s:%d", mythicConfig.MythicConfig.MythicServerHost, mythicConfig.MythicConfig.MythicServerPort)
		req.URL.Path = "/agent_message"
		req.Header.Add("mythic", "http")
	}
	proxy := &httputil.ReverseProxy{Director: director,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:    10,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}}
	// each route is "/someWord" with an optional "/somethingElse" afterwards
	r.GET("/:val/*action", getRequest(configInstance, proxy))
	r.POST("/:val/*action", postRequest(configInstance, proxy))
	r.GET("/:val", getRequest(configInstance, proxy))
	r.POST("/:val", postRequest(configInstance, proxy))
	r.GET("/", getRequest(configInstance, proxy))
	r.POST("/", postRequest(configInstance, proxy))
	if len(configInstance.PayloadHostPaths) > 0 {
		for path, value := range configInstance.PayloadHostPaths {
			localVal := value
			directorForFiles := func(req *http.Request) {
				req.URL.Scheme = "http"
				req.URL.Host = fmt.Sprintf("%s:%d", mythicConfig.MythicConfig.MythicServerHost, mythicConfig.MythicConfig.MythicServerPort)
				req.Host = fmt.Sprintf("%s:%d", mythicConfig.MythicConfig.MythicServerHost, mythicConfig.MythicConfig.MythicServerPort)
				req.URL.Path = fmt.Sprintf("/direct/download/%s", localVal)
			}
			proxyForFiles := httputil.ReverseProxy{Director: directorForFiles,
				Transport: &http.Transport{
					DialContext: (&net.Dialer{
						Timeout: 30 * time.Second,
					}).DialContext,
					MaxIdleConns:    10,
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				}}
			r.GET(path, generateServeFile(configInstance, fmt.Sprintf("%s", localVal), &proxyForFiles))
		}
	}
}

func generateServeFile(configInstance instanceConfig, fileUUID string, proxyForFiles *httputil.ReverseProxy) gin.HandlerFunc {

	if configInstance.Debug {
		logging.LogInfo("debug route", "host", mythicConfig.MythicConfig.MythicServerHost, "path", "/direct/download/"+fileUUID)
	}
	return func(c *gin.Context) {
		if c.Request.Header.Get("X-Forwarded-For") == "" {
			c.Request.Header.Set("X-Forwarded-For", c.ClientIP())
		}
		proxyForFiles.ServeHTTP(c.Writer, c.Request)
	}
}

func getRequest(configInstance instanceConfig, proxy *httputil.ReverseProxy) gin.HandlerFunc {
	if configInstance.Debug {
		logging.LogInfo("debug route", "host", mythicConfig.MythicConfig.MythicServerHost, "path", "/agent_message")
	}
	return func(c *gin.Context) {
		for header, val := range configInstance.Headers {
			c.Header(header, val)
		}
		if c.Request.Header.Get("X-Forwarded-For") == "" {
			c.Request.Header.Set("X-Forwarded-For", c.ClientIP())
		}
		proxy.ServeHTTP(c.Writer, c.Request)
	}
}

func postRequest(configInstance instanceConfig, proxy *httputil.ReverseProxy) gin.HandlerFunc {
	if configInstance.Debug {
		logging.LogInfo("debug route", "host", mythicConfig.MythicConfig.MythicServerHost, "path", "/agent_message")
	}
	return func(c *gin.Context) {
		for header, val := range configInstance.Headers {
			c.Header(header, val)
		}
		if c.Request.Header.Get("X-Forwarded-For") == "" {
			c.Request.Header.Set("X-Forwarded-For", c.ClientIP())
		}
		proxy.ServeHTTP(c.Writer, c.Request)
	}
}

// code to generate self-signed certs pulled from github.com/kabukky/httpscerts
// and from http://golang.org/src/crypto/tls/generate_cert.go.
// only modifications were to use a specific elliptic curve cipher
func checkCerts(certPath string, keyPath string) error {
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return err
	} else if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return err
	}
	return nil
}
func generateCerts(configInstance instanceConfig) error {

	logging.LogInfo("[*] generating certs now...")
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		logging.LogError(err, "failed to generate private key")
		return err
	}
	notBefore := time.Now()
	oneYear := 365 * 24 * time.Hour
	notAfter := notBefore.Add(oneYear)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		logging.LogError(err, "failed to generate serial number")
		return err
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Mythic C2"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		logging.LogError(err, "failed to create certificate")
		return err
	}
	certOut, err := os.Create(configInstance.CertPath)
	if err != nil {
		logging.LogError(err, "failed to open "+configInstance.CertPath+" for writing")
		return err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()
	keyOut, err := os.OpenFile(configInstance.KeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		logging.LogError(err, "failed to open "+configInstance.KeyPath+" for writing")
		return err
	}
	marshalKey, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		logging.LogError(err, "Unable to marshal ECDSA private key")
		return err
	}
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: marshalKey})
	keyOut.Close()
	logging.LogInfo("Successfully generated new SSL certs\n")
	return nil
}
