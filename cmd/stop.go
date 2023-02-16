package cmd

import (
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

// Command to stop the execution of Scaling Manager
var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop Opensearch Scaling Manager",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		err := stop()
		if err != nil {
			log.Error.Println(err)
			return
		}
		log.Info.Println("Stop Successful")
	},
}

// Input:
//
// Description:
//
//		Function reads the Process Id file and stops the running instance
//	 of Scaling Manager.
//
// Return:
//
// (error): Returns error upon unsuccessful execution.
func stop() error {
	log.Info.Println("Stopping Scale Manager")

	_, err := os.Stat(PidFilePath + "/pidFile")
	if err != nil {
		log.Error.Println("Process not found ", err)
		return err
	}

	fileByte, err := os.ReadFile(PidFilePath + "/pidFile")
	if err != nil {
		log.Error.Println("Process id file not found ", err)
		return err
	}

	pid, err := strconv.Atoi(string(fileByte))
	if err != nil {
		log.Error.Println(err)
		return err
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		log.Error.Println("Process not found ", err)
		return err
	}

	err = proc.Signal(os.Interrupt)
	if err != nil {
		log.Error.Println("Unable to terminate process ", err)
		return err
	}

	err = os.Remove(PidFilePath + "/pidFile")
	if err != nil {
		log.Error.Println("Unable to delete pid file ", err)
		return err
	}

	return nil
}
