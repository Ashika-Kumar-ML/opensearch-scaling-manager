package cmd 
  
import (
        "github.com/spf13/cobra"
)

// Root command which tracks and creates heirarchy of commands
var scaleManagerCmd  = &cobra.Command{
    Use:   "scale_manager",
    Short: "Opensearch Scaling Manager",
}

// Input:
// 
// Description:
// 	
//	Function executes the command provided by user through CLI
// 
// Return:
// 
// 	(error): Returns error upon unsuccessful execution
func Execute() error{
        return scaleManagerCmd.Execute()
}

// Input:
// 
// Description:
// 
// 	Initializes the root command by adding all commands that are 
//  accessible to the user
// 
// Return:
func init(){
        scaleManagerCmd.AddCommand(startCmd)
        scaleManagerCmd.AddCommand(stopCmd)
}
