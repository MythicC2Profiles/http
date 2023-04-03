package c2functions

import (
	"encoding/json"
	"fmt"
	c2structs "github.com/MythicMeta/MythicContainer/c2_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"net"
	"os"
	"path/filepath"
	"strings"
)

type config struct {
	Instances []instanceConfig `json:"instances"`
}
type instanceConfig struct {
	Port             int               `json:"port"`
	KeyPath          string            `json:"key_path"`
	CertPath         string            `json:"cert_path"`
	Debug            bool              `json:"debug"`
	UseSSL           bool              `json:"use_ssl"`
	PayloadHostPaths map[string]string `json:"payloads"`
}

func getC2JsonConfig() (*config, error) {
	currentConfig := config{}
	if configBytes, err := os.ReadFile(filepath.Join(".", "http", "c2_code", "config.json")); err != nil {
		return nil, err
	} else if err = json.Unmarshal(configBytes, &currentConfig); err != nil {
		logging.LogError(err, "Failed to unmarshal config bytes")
		return nil, err
	} else {
		return &currentConfig, nil
	}
}

var httpc2definition = c2structs.C2Profile{
	Name:             "http",
	Author:           "@its_a_feature_",
	Description:      "Uses HTTP Get/Post messages for connectivity",
	IsP2p:            false,
	IsServerRouted:   true,
	ServerBinaryPath: filepath.Join(".", "http", "c2_code", "mythic_http_server"),
	ConfigCheckFunction: func(message c2structs.C2ConfigCheckMessage) c2structs.C2ConfigCheckMessageResponse {
		response := c2structs.C2ConfigCheckMessageResponse{
			Success: true,
			Message: fmt.Sprintf("Called config check\n%v", message),
		}
		if suppliedPort, ok := message.Parameters["callback_port"]; !ok {
			response.Success = false
			response.Error = "Failed to get callback_port attribute"
			return response
		} else if suppliedHost, ok := message.Parameters["callback_host"]; !ok {
			response.Success = false
			response.Error = "Failed to get callback_host attribute"
			return response
		} else if currentConfig, err := getC2JsonConfig(); err != nil {
			response.Success = false
			response.Error = err.Error()
			return response
		} else {
			possibleSSLPorts := []int{}
			possiblePorts := []int{}
			parameterPort := int(suppliedPort.(float64))
			parameterHost := suppliedHost.(string)
			for _, instance := range currentConfig.Instances {
				if instance.UseSSL {
					possibleSSLPorts = append(possibleSSLPorts, instance.Port)
				} else {
					possiblePorts = append(possiblePorts, instance.Port)
				}
				if instance.Port == parameterPort {
					// we found a match for our port and a configured port
					if strings.HasPrefix(parameterHost, "https") && !instance.UseSSL {
						// callback_host of https:// on port, but port isn't configured with ssl
						message := fmt.Sprintf("C2 Profile container is configured to NOT use SSL on port %d, but the callback host for the agent is using https, %s.\n\n",
							instance.Port, parameterHost)
						message += "This means there should be the following connectivity for success:\n"
						message += fmt.Sprintf("Agent via SSL to %s on port %d, then redirection to C2 Profile container WITHOUT SSL on port %d",
							parameterHost, parameterPort, parameterPort)
						response.Error = message
						response.Success = false
						return response
					} else if !strings.HasPrefix(parameterHost, "https") && instance.UseSSL {
						// callback_host of http:// on port, but port is configured with ssl
						message := fmt.Sprintf("C2 Profile container is configured to use SSL on port %d, but the callback host for the agent is using http, %s.\n\n",
							instance.Port, parameterHost)
						message += "This means there should be the following connectivity for success:\n"
						message += fmt.Sprintf("Agent via NO SSL to %s on port %d, then redirection to C2 Profile container WITH SSL on port %d",
							parameterHost, parameterPort, parameterPort)
						response.Error = message
						response.Success = false
						return response
					} else {
						// either http:// on port without ssl or https:// on port with ssl, all good
						response.Message = fmt.Sprintf("C2 Profile container and agent configuration match port, %d, and SSL expectations (%v)\n",
							instance.Port, instance.UseSSL)
						return response
					}
				}
			}
			message := fmt.Sprintf("Failed to find port, %d, in C2 Profile configuration\n",
				parameterPort)
			message += "This could indicate the use of a redirector, or a mismatch in expected connectivity.\n\n"
			message += "This means there should be the following connectivity for success:\n"
			if strings.HasPrefix(parameterHost, "https") {
				message += fmt.Sprintf("Agent via HTTPS on port %d to %s (should be a redirector).\n",
					parameterPort, parameterHost)
			} else {
				message += fmt.Sprintf("Agent via HTTP on port %d to %s (should be a redirector).\n",
					parameterPort, parameterHost)
			}
			if len(possibleSSLPorts) > 0 {
				message += fmt.Sprintf("Redirector then forwards request to C2 Profile container WITH SSL on one of the following ports: %v\n",
					possibleSSLPorts)
			}
			if len(possiblePorts) > 0 {
				if len(possibleSSLPorts) > 0 {
					message += fmt.Sprintf("Alternatively, redirector could forward request to C2 Profile container WITHOUT SSL on one of the following ports: %v\n",
						possiblePorts)
				} else {
					message += fmt.Sprintf("Redirector then forwards request to C2 Profile container WITHOUT SSL on one of the following ports: %v\n",
						possiblePorts)
				}
			}
			if strings.HasPrefix(parameterHost, "https") {
				message += "\nAlternatively, this might mean that you want to do SSL but are not using SSL within your C2 Profile container.\n"
				message += "To add SSL to your C2 profile:\n"
				message += "\t1. Go to the C2 Profile page\n"
				message += "\t2. Click configure for the http profile\n"
				message += fmt.Sprintf(
					"\t3. Change 'use_ssl' to 'true' and make sure the port is %d}\n",
					parameterPort)
				message += "\t4. Click to stop the profile and then start it again\n"
			}
			response.Message = message
			return response
		}
	},
	GetRedirectorRulesFunction: func(message c2structs.C2GetRedirectorRuleMessage) c2structs.C2GetRedirectorRuleMessageResponse {
		response := c2structs.C2GetRedirectorRuleMessageResponse{
			Success: true,
			Message: fmt.Sprintf("Called redirector status check:\n%v", message),
		}
		output := "mod_rewrite rules generated from @AndrewChiles' project https://github.com/threatexpress/mythic2modrewrite:\n"
		errors := ""
		ua := ""
		uris := []string{}
		if headersInterface, ok := message.Parameters["headers"]; !ok {
			errors += "[!] Headers c2 profile parameter not found\n"
		} else {
			headers := headersInterface.(map[string]interface{})
			if userAgent, ok := headers["User-Agent"]; !ok {
				errors += "[!] User-Agent not found in headers\n"
			} else {
				ua = userAgent.(string)
			}
		}
		if getURI, ok := message.Parameters["get_uri"]; !ok {
			errors += "[!] No GET URI found\n"
		} else {
			uris = append(uris, "/"+getURI.(string))
		}
		if postURI, ok := message.Parameters["post_uri"]; !ok {
			errors += "[!] No POST URI found\n"
		} else {
			uris = append(uris, "/"+postURI.(string))
		}
		// Create UA in modrewrite syntax. No regex needed in UA string matching, but () characters must be escaped
		uaString := strings.ReplaceAll(ua, "(", "\\(")
		uaString = strings.ReplaceAll(uaString, ")", "\\)")
		// Create URI string in modrewrite syntax. "*" are needed in regex to support GET and uri-append parameters on the URI
		urisString := strings.Join(uris, ".*|") + ".*"
		c2RewriteTemplate := "RewriteRule ^.*$ \"%s%%{{REQUEST_URI}}\" [P,L]"
		c2RewriteOutput := []string{}
		if netifaces, err := net.InterfaceAddrs(); err != nil {
			logging.LogError(err, "Failed to get interface addresses")
			c2RewriteOutput = []string{"RewriteRule ^.*$ \"%s%{{REQUEST_URI}}\" [P,L]"}
		} else if currentConfig, err := getC2JsonConfig(); err != nil {
			logging.LogError(err, "Failed to get current json configuration")
			c2RewriteOutput = []string{"RewriteRule ^.*$ \"%s%{{REQUEST_URI}}\" [P,L]"}
		} else {
			for _, iface := range netifaces {
				if !iface.(*net.IPNet).IP.IsLoopback() && !iface.(*net.IPNet).IP.IsPrivate() {
					if iface.(*net.IPNet).IP.To4() != nil {
						// have a non loopback, non-private ip for redirection
						for _, instance := range currentConfig.Instances {
							if instance.UseSSL {
								serverURL := fmt.Sprintf("https://%s:%d", iface.(*net.IPNet).IP.String(), instance.Port)
								c2RewriteOutput = append(c2RewriteOutput, fmt.Sprintf(c2RewriteTemplate, serverURL))
							} else {
								serverURL := fmt.Sprintf("http://%s:%d", iface.(*net.IPNet).IP.String(), instance.Port)
								c2RewriteOutput = append(c2RewriteOutput, fmt.Sprintf(c2RewriteTemplate, serverURL))
							}
						}
					}
				}
			}
			if len(c2RewriteOutput) == 0 {
				c2RewriteOutput = []string{"c2server"}
				output += "\tReplace 'c2server' with the http(s) address of where matching traffic should go\n"
				output += "\t\tFailed to automatically determine public IP address\n"
			}
		}
		htaccessTemplate := `
########################################
## .htaccess START
RewriteEngine On
## C2 Traffic (HTTP-GET, HTTP-POST, HTTP-STAGER URIs)
## Logic: If a requested URI AND the User-Agent matches, proxy the connection to the Teamserver
## Consider adding other HTTP checks to fine tune the check.  (HTTP Cookie, HTTP Referer, HTTP Query String, etc)
## Refer to http://httpd.apache.org/docs/current/mod/mod_rewrite.html
## Only allow GET and POST methods to pass to the C2 server
RewriteCond %%{{REQUEST_METHOD}} ^(GET|POST) [NC]
## Profile URIs
RewriteCond %%{{REQUEST_URI}} ^({%s})$
## Profile UserAgent
RewriteCond %%{{HTTP_USER_AGENT}} "{%s}"
{%s}
## Redirect all other traffic here
RewriteRule ^.*$ {redirect}/? [L,R=302]
## .htaccess END
########################################
		`
		htaccess := fmt.Sprintf(htaccessTemplate, urisString, uaString, strings.Join(c2RewriteOutput, "\n"))
		output += "\tReplace 'redirect' with the http(s) address of where non-matching traffic should go, ex: https://redirect.com\n"
		output += "\n" + htaccess
		response.Message = output
		return response
	},
	OPSECCheckFunction: func(message c2structs.C2OPSECMessage) c2structs.C2OPSECMessageResponse {
		response := c2structs.C2OPSECMessageResponse{
			Success: true,
			Message: fmt.Sprintf("Called opsec check:\n%v", message),
		}
		if callbackHost, ok := message.Parameters["callback_host"]; !ok {
			response.Success = false
			response.Error = "Failed to get callback_host attribute"
			return response
		} else if callbackPort, ok := message.Parameters["callback_port"]; !ok {
			response.Success = false
			response.Error = "Failed to get callback_port attribute"
			return response
		} else if callbackHost.(string) == "https://domain.com" {
			response.Success = false
			response.Error = "Callback Host is set to default of https://domain.com!\n"
			return response
		} else if len(strings.Split(callbackHost.(string), ":")) != 2 {
			response.Success = false
			response.Error = fmt.Sprintf("callback host is improperly configured! %v shouldn't specify a port, that should be in the callback_port field", callbackHost)
			return response
		} else if strings.HasPrefix(callbackHost.(string), "https") {
			standardHttpsPorts := []int{443, 8443, 7443}
			for _, port := range standardHttpsPorts {
				if port == int(callbackPort.(float64)) {
					return response
				}
			}
			response.Success = true
			response.Message = fmt.Sprintf("Callback port, %d, is unusual for https scheme", int(callbackPort.(float64)))
			return response
		} else {
			response.Message = "No immediate issues with configuration"
			return response
		}
	},
}
var httpc2parameters = []c2structs.C2Parameter{
	{
		Name:          "callback_port",
		Description:   "Callback Port",
		DefaultValue:  80,
		ParameterType: c2structs.C2_PARAMETER_TYPE_NUMBER,
		Required:      false,
		VerifierRegex: "^[0-9]+$",
	},
	{
		Name:          "killdate",
		Description:   "Kill Date",
		DefaultValue:  365,
		ParameterType: c2structs.C2_PARAMETER_TYPE_DATE,
		Required:      false,
	},
	{
		Name:          "encrypted_exchange_check",
		Description:   "Perform Key Exchange",
		DefaultValue:  true,
		ParameterType: c2structs.C2_PARAMETER_TYPE_BOOLEAN,
		Required:      false,
	},
	{
		Name:          "callback_jitter",
		Description:   "Callback Jitter in percent",
		DefaultValue:  23,
		ParameterType: c2structs.C2_PARAMETER_TYPE_NUMBER,
		Required:      false,
		VerifierRegex: "^[0-9]+$",
	},
	{
		Name:          "headers",
		Description:   "HTTP Headers",
		ParameterType: c2structs.C2_PARAMETER_TYPE_DICTIONARY,
		Required:      false,
		DictionaryChoices: []c2structs.C2ParameterDictionary{
			{
				Name:         "User-Agent",
				DefaultShow:  true,
				DefaultValue: "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
			},
			{
				Name:         "Host",
				DefaultShow:  false,
				DefaultValue: "",
			},
		},
	},
	{
		Name:          "AESPSK",
		Description:   "Encryption Type",
		DefaultValue:  "aes256_hmac",
		ParameterType: c2structs.C2_PARAMETER_TYPE_CHOOSE_ONE,
		Required:      false,
		IsCryptoType:  true,
		Choices: []string{
			"aes256_hmac",
			"none",
		},
	},
	{
		Name:          "callback_host",
		Description:   "Callback Host",
		DefaultValue:  "https://domain.com",
		ParameterType: c2structs.C2_PARAMETER_TYPE_STRING,
		Required:      true,
		VerifierRegex: "^(http|https):\\/\\/[a-zA-Z0-9]+",
	},
	{
		Name:          "get_uri",
		Description:   "GET request URI (don't include leading /)",
		DefaultValue:  "index",
		ParameterType: c2structs.C2_PARAMETER_TYPE_STRING,
		Required:      false,
	},
	{
		Name:          "post_uri",
		Description:   "POST request URI (don't include leading /)",
		DefaultValue:  "data",
		ParameterType: c2structs.C2_PARAMETER_TYPE_STRING,
		Required:      false,
	},
	{
		Name:          "query_path_name",
		Description:   "Name of the query parameter for GET requests",
		DefaultValue:  "q",
		ParameterType: c2structs.C2_PARAMETER_TYPE_STRING,
		Required:      false,
		VerifierRegex: "^[^\\/]",
	},
	{
		Name:          "proxy_host",
		Description:   "Proxy Host",
		DefaultValue:  "",
		ParameterType: c2structs.C2_PARAMETER_TYPE_STRING,
		Required:      false,
		VerifierRegex: "^$|^(http|https):\\/\\/[a-zA-Z0-9]+",
	},
	{
		Name:          "proxy_port",
		Description:   "Proxy Port",
		DefaultValue:  "",
		ParameterType: c2structs.C2_PARAMETER_TYPE_STRING,
		Required:      false,
		VerifierRegex: "^$|^[0-9]+$",
	},
	{
		Name:          "proxy_user",
		Description:   "Proxy Username",
		DefaultValue:  "",
		ParameterType: c2structs.C2_PARAMETER_TYPE_STRING,
		Required:      false,
	},
	{
		Name:          "proxy_pass",
		Description:   "Proxy Password",
		DefaultValue:  "",
		ParameterType: c2structs.C2_PARAMETER_TYPE_STRING,
		Required:      false,
	},
	{
		Name:          "callback_interval",
		Description:   "Callback Interval in seconds",
		DefaultValue:  10,
		ParameterType: c2structs.C2_PARAMETER_TYPE_NUMBER,
		Required:      false,
		VerifierRegex: "^[0-9]+$",
	},
}

func Initialize() {
	c2structs.AllC2Data.Get("http").AddC2Definition(httpc2definition)
	c2structs.AllC2Data.Get("http").AddParameters(httpc2parameters)
}
