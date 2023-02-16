package main

import (
	"log"
	"os"
	"os/signal"

	"github.com/maplelabs/opensearch-scaling-manager/cmd"
	app "github.com/maplelabs/opensearch-scaling-manager/scaleManager"
)

// Input:
//
// Description:
//
//		The entry point for the execution of this application
//	 The function takes commands(start,stop) to start
//	 and stop the Scaling Manager service.
//
// Return:
func main() {

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		app.CleanUp()
	}()

	err := cmd.Execute()
	if err != nil && err.Error() != "" {
		log.Fatal(err)
	}

}
