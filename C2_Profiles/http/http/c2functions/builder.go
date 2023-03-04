package c2functions

import (
	c2structs "github.com/MythicMeta/MythicContainer/c2_structs"
	"path/filepath"
)

var httpc2definition = c2structs.C2Profile{
	Name:             "http",
	Author:           "@its_a_feature_",
	Description:      "this is a test description",
	IsP2p:            false,
	IsServerRouted:   true,
	ServerBinaryPath: filepath.Join(".", "http", "c2_code", "mythic_http_server"),
	ConfigCheckFunction: func(message c2structs.C2ConfigCheckMessage) c2structs.C2ConfigCheckMessageResponse {
		response := c2structs.C2ConfigCheckMessageResponse{
			Success: true,
			Message: "Called config check",
		}
		return response
	},
	GetRedirectorRulesFunction: func(message c2structs.C2GetRedirectorRuleMessage) c2structs.C2GetRedirectorRuleMessageResponse {
		response := c2structs.C2GetRedirectorRuleMessageResponse{
			Success: true,
			Message: "Called redirector status check",
		}
		return response
	},
	OPSECCheckFunction: func(message c2structs.C2OPSECMessage) c2structs.C2OPSECMessageResponse {
		response := c2structs.C2OPSECMessageResponse{
			Success: true,
			Message: "Called opsec check",
		}
		return response
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
		Description:   "Name of the query parameter for GET requests",
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
		DefaultValue:  "q",
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
