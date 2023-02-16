package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"os/exec"

	"github.com/maplelabs/opensearch-scaling-manager/logger"
	app "github.com/maplelabs/opensearch-scaling-manager/scaleManager"
)

// Directory Path to store the PID file
var PidFilePath = "/var/run"

// Logger variable used across the package for logging.
var log logger.LOG

// Start Command to start the Scaling Manager service
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start Opensearch Scaling Manager",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		bg, _ := cmd.Flags().GetString("b")

		if bg != "" {
			if bg != "true" {
				log.Fatal.Println("Unknown value for flag")
				os.Exit(1)
			}
			log.Info.Println("Started scale manager in background")
			startBackground()
		} else {
			err := start()
			if err != nil {
				log.Error.Println(err)
			}
		}
	},
}

// Input:
//
// Description:
// 	Initializes the start command, adds the required flags
//
// Return:
func init() {
	startCmd.PersistentFlags().String("b", "", "Flag to run process in background")
	log.Init("logger")
}

// Input:
//
// Description:
//
// 	The Function initilazes and starts the execution of Scaling Manager
//
// Return:
//
// 	(error): Returns error upon unsuccessful execution
func start() error {
	app.Initialize()
	app.Run()
	return nil
}

// Input:
//
// Description:
//
// 	The Function is executed when user sets flag(--b=true) along
// 	with start command. It creates a Background process and creates
// 	a file to track the Process Id of the background process.
//
// Return:
//
// 	(error): Returns error upon unsuccessful execution.
func startBackground() error {
	_, err := os.Stat(PidFilePath + "/pidFile")

	if err != nil {
		scaleManagerExe, err := os.Executable()
		if err != nil {
			log.Error.Println(err)
			return err
		}

		cmd := exec.Command(scaleManagerExe, "start")

		err = cmd.Start()
		if err != nil {
			log.Error.Println(err)
			return err
		}

		log.Info.Printf("Scale Manager started with pid %v", cmd.Process.Pid)

		pidFile, createFileErr := os.Create(PidFilePath + "/pidFile")
		if createFileErr != nil {
			log.Error.Println(createFileErr)
			return createFileErr
		}
		defer pidFile.Close()

		_, writeErr := pidFile.Write([]byte(fmt.Sprintf("%v", cmd.Process.Pid)))
		if writeErr != nil {
			log.Error.Println(writeErr)
			return writeErr
		}
		return nil
	}

	log.Info.Println("Process already running")
	fileByte, err := os.ReadFile("pidFile")
	if err != nil {
		log.Error.Println(err)
	}

	log.Info.Printf("Process already running with pid %v ", string(fileByte))
	return nil
}
