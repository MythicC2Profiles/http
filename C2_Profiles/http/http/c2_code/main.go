package main

import (
	"mythicHTTP/webserver"
	"github.com/MythicMeta/MythicContainer/logging"
)

func main() {
	webserver.InitializeLocalConfig()
	for index, instance := range webserver.Config.Instances {
		logging.LogInfo("Initializing webserver", "instance", index+1)
		router := webserver.Initialize(instance)
		// start serving up API routes
		logging.LogInfo("Starting webserver", "instance", index+1)
		webserver.StartServer(router, instance)
	}
	forever := make(chan bool)
	<-forever

}
