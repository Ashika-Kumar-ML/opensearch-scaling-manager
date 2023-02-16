package ansibleutils

import (
	"context"

	"encoding/json"
	"errors"
	"github.com/apenella/go-ansible/pkg/execute"
	"github.com/apenella/go-ansible/pkg/options"
	"github.com/apenella/go-ansible/pkg/playbook"
	"github.com/apenella/go-ansible/pkg/stdoutcallback/results"
	"github.com/maplelabs/opensearch-scaling-manager/config"
	"github.com/maplelabs/opensearch-scaling-manager/logger"
	"regexp"
)

var log = new(logger.LOG)

// Input:
//
// Description:
//
//	Initialize the Ansible module.
//
// Return:
func init() {
	log.Init("logger")
	log.Info.Println("Ansible module initiated")
}

// Input:
//
//	username (string): Username string to be used to ssh into the host inventory
//	hosts (string): The file name of hosts file to pass to ansible playbook
//	clusterCfg (config.ClusterDetails): Opensearch cluster details for configuring
//	operation (string): Operation called scale_up/scale_down
//
// Description:
//
//	Calls the ansible script responsible for adding a new node into the Opensearch cluster and configuring it or removing a node and shut it down
//
// Return:
//
//	(error): Returns error if any
func CallAnsible(username string, hosts string, clusterCfg config.ClusterDetails, operation string) error {

	var fileName string
	switch operation {
	case "scale_up":
		fileName = "ansible_scripts/scaleUpPlaybook.yml"
	case "scale_down":
		fileName = "ansible_scripts/scaleDownPlaybook.yml"
	case "copy_config":
		fileName = "ansible_scripts/install_scaling_manager.yaml"
	}

	var variablesMap map[string]interface{}
	jsonData, err := json.Marshal(&clusterCfg)
	if err != nil {
		log.Error.Println("Error while Marshaling")
		return err
	}

	err = json.Unmarshal(jsonData, &variablesMap)
	if err != nil {
		log.Error.Println("json parsing error")
		return err
	}

	ansiblePlaybookConnectionOptions := &options.AnsibleConnectionOptions{
		User: username,
	}

	ansiblePlaybookOptions := &playbook.AnsiblePlaybookOptions{
		Inventory: hosts,
		ExtraVars: variablesMap,
	}

	ansiblePlaybookPrivilegeEscalationOptions := &options.AnsiblePrivilegeEscalationOptions{
		Become: true,
	}

	playbook := &playbook.AnsiblePlaybookCmd{
		Playbooks:                  []string{fileName},
		ConnectionOptions:          ansiblePlaybookConnectionOptions,
		PrivilegeEscalationOptions: ansiblePlaybookPrivilegeEscalationOptions,
		Options:                    ansiblePlaybookOptions,
		Exec: execute.NewDefaultExecute(
			execute.WithEnvVar("ANSIBLE_FORCE_COLOR", "true"),
			execute.WithTransformers(
				results.Prepend("Go-ansible with become"),
			),
		),
	}

	err = playbook.Run(context.TODO())
	if err != nil {
		return maskCredentials(err)
	}
	return nil
}

// Input:
//
//	err (error): Error from which credentials are to be masked
//
// Description:
//
//	Masks the credentials from error string.
//
// Return:
//
//	(error): Returns custom error
func maskCredentials(err error) error {
	errString := err.Error()
	m1 := regexp.MustCompile("\"*credentials\":.*?}")
	errString = m1.ReplaceAllString(errString, "credentials\":{*********}")
	errString = errString + "\nCheck ansible log file for more details. (ansible_scripts/playbook.log)"
	err = errors.New(errString)
	return err
}
