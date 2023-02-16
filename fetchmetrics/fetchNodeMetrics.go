package fetchmetrics

import (
	"context"
	"encoding/json"
	"os/exec"
	"github.com/maplelabs/opensearch-scaling-manager/cluster"
	osutils "github.com/maplelabs/opensearch-scaling-manager/opensearchUtils"
	utils "github.com/maplelabs/opensearch-scaling-manager/utilities"
	"strconv"
	"strings"
)

// Description: NodeMetrics struct holds the node level metrics that are to be populated and indexed to elasticsearch
type NodeMetrics struct {
	cluster.Node
	Timestamp     int64
	StatTag       string
	_documentType string
}

// Input:
//
//	m(map[string]interface): Holds the node stats response
//	nodeId(string): Unique id which is used to access the response of corresponding node.
//
// Description:
//
//	The function calculates and returns disk utilization.
//	The disk utilization is fetched from the node stats response from elasticsearch, there is no difference in terms
//	of output when we fetch from linux or elasticsearch. And to fetch from the linux we need to make a call to elasticsearch
//	to find where the binary of es is installed, when we make this call we get the disk utilization along with the mount path
//	hence the overhead of calculating from linux is minimized by making use of response from elasticsearch.
//
// Return:
//
//	(float32): Returns the disk utilization of the node
func getDiskUtil(m map[string]interface{}, nodeId string) float32 {
	//Parse the node stats interface for required info
	list := m["nodes"].(map[string]interface{})[nodeId].(map[string]interface{})["fs"].(map[string]interface{})["data"].([]interface{})
	listJson, err := json.MarshalIndent(list[0], "", " ")
	if err != nil {
		log.Error.Println("Cannot marshall: ", err)
	}
	var listInterface map[string]interface{}
	err1 := json.Unmarshal(listJson, &listInterface)
	if err1 != nil {
		log.Error.Println("Unmarshal Error: ", err1)
	}
	// disk utilization = ((total space - available space) / total space) *100
	return float32(((listInterface["total_in_bytes"].(float64) - listInterface["available_in_bytes"].(float64)) / listInterface["total_in_bytes"].(float64)) * 100)
}

// Input:
// Description:
//
//	The functions fetchs CPU utilization directly from system through linux commands
//
// Output:
//
//	(float32): Returns CPU utilization of system
func getCpuUtil() float32 {
	//Executing the top command to fetch the CPU utilization
	cmd := exec.Command("bash", "-c", "top -bn2 | grep '%Cpu' | tail -1 | awk '{print 100-$8}'")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Error.Println("error: ", out)
	}

	//Converting the result to float
	cpuFloat, err := strconv.ParseFloat(strings.TrimSuffix(string(out), "\n"), 8)
	if err != nil {
		log.Error.Println("Unable to convert to float: ", err)
	}
	return float32(cpuFloat)
}

// Input:
// Description:
//
//	The functions fetchs Memory utilization directly from system through linux commands
//
// Return:
//
//	(float32): Returns the memory utilization of the system.
func getRamUtil() float32 {
	//Executing the top command to fetch the memory utilization
	cmd := exec.Command("bash", "-c", "top -bn2 | grep -E '[KiB|MiB|GiB] Mem' | tail -1 | awk '{print ($8/$4)*100}'")
	memout, err := cmd.CombinedOutput()
	if err != nil {
		log.Error.Println(err)
	}

	//Converting the result to float
	memFloat, err := strconv.ParseFloat(strings.TrimSuffix(string(memout), "\n"), 8)
	if err != nil {
		log.Error.Println("Unable to convert to float: ", err)
	}

	return float32(memFloat)
}

// Input:
//
//	ctx (context.Context): Request-scoped data that transits processes and APIs.
//
// Description:
//
//	The function fetches node stats through API call and indexes it to opensearch.
//
// Return:
func IndexNodeStats(ctx context.Context) {

	nodeMetrics := new(NodeMetrics)

	//creating a node stats requests with filter to reduce the response to requirement
	nodes := []string{"_local"}
	metrics := []string{"jvm", "os", "fs", "indices"}
	nodeStatResp, err := osutils.GetNodeStats(ctx, nodes, metrics)
	if err != nil {
		log.Error.Println("Node stat fetch error: ", err)
	}
	defer nodeStatResp.Body.Close()

	//A map to dump the values from node stats response
	var nodeStatsInterface map[string]interface{}

	//Decoding the response into the the interface
	decodeErr := json.NewDecoder(nodeStatResp.Body).Decode(&nodeStatsInterface)
	if decodeErr != nil {
		log.Error.Println("decode Error: ", decodeErr)
	}

	catAllocationResp, catErr := osutils.CatAllocation(ctx, nodes)
	if catErr != nil {
		log.Error.Println("Cat allocation fetch error: ", catErr)
	}
	defer catAllocationResp.Body.Close()

	var catAllocationInterface interface{}

	decodeErr = json.NewDecoder(catAllocationResp.Body).Decode(&catAllocationInterface)
	if decodeErr != nil {
		log.Error.Println("decode Error: ", decodeErr)
	}

	nodeMetrics.NumShards = int(catAllocationInterface.(float64))

	//parsing the interface and populating the node stats structure
	nodeId := utils.ParseNodeId(nodeStatsInterface["nodes"].(map[string]interface{}))
	nodeInfo := nodeStatsInterface["nodes"].(map[string]interface{})[nodeId].(map[string]interface{})
	nodeMetrics.NodeId = nodeId
	nodeMetrics.NodeName = nodeInfo["name"].(string)
	nodeMetrics.Timestamp = int64(nodeInfo["timestamp"].(float64))
	nodeMetrics.HostIp = nodeInfo["host"].(string)
	nodeMetrics.IsMaster = utils.CheckIfMaster(ctx, nodeId)
	for _, role := range nodeInfo["roles"].([]interface{}) {
		if role == "data" {
			nodeMetrics.IsData = true
		}
	}
	nodeMetrics.CpuUtil = getCpuUtil()
	nodeMetrics.RamUtil = getRamUtil()
	nodeMetrics.HeapUtil = float32(nodeInfo["jvm"].(map[string]interface{})["mem"].(map[string]interface{})["heap_used_percent"].(float64))
	nodeMetrics.DiskUtil = getDiskUtil(nodeStatsInterface, nodeId)
	nodeMetrics.StatTag = "NodeStatistics"
	nodeMetrics._documentType = "NodeStatistics"

	//marshall the node metrics, to index into the elasticsearch
	nodeMetricsJson, jsonErr := json.MarshalIndent(nodeMetrics, "", "\t")
	if jsonErr != nil {
		log.Error.Println("Error converting struct to Json: ", jsonErr)
	}

	resp, err := osutils.IndexMetrics(ctx, nodeMetricsJson)
	if err != nil {
		log.Panic.Println("Error indexing document: ", err)
		panic(err)
	}
	defer resp.Body.Close()
	log.Info.Println("Node document indexed successfully")
}
