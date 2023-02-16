// This package provide the data structure needed to get the metrics.
// There are two kind of metrics:
//
//	Cluster metrics: This data structure will provide cluster level metrics.
//	Node metrics: This data structure will provide node level metrics.
//
// The cluster metrics contains list of the node metrics collected over all the nodes present in a cluster.
// The package contains a struct called MetricStatsCluster which will calculate the statistics over a period of time.
// The package contains a struct called MetricViolatedCountCluster which will calculate the violated count over a period of time.
// The structs be used by recommendation module.
package cluster

import (
	"context"
	"encoding/json"
	"github.com/maplelabs/opensearch-scaling-manager/logger"
	osutils "github.com/maplelabs/opensearch-scaling-manager/opensearchUtils"
	"strconv"
)

var log logger.LOG

// Input:
//
// Description:
//
//	Initialize the cluster module.
//
// Return:
func init() {
	log.Init("logger")
	log.Info.Println("Cluster module initialized")
}

// This struct will contain node metrics for a node in the OpenSearch cluster.
type Node struct {
	// NodeId indicates a unique ID of the node given by OpenSearch.
	NodeId string
	// NodeName indicates human-readable identifier for a particular instance of OpenSearch which is a configurable input.
	NodeName string
	// HostIp indicates the IP address of the node.
	HostIp string
	// IsMater indicates if the node is a master node.
	IsMaster bool
	// IsData indicates if the node is a data node.
	IsData bool
	// CpuUtil indicates the overall CPU Utilization in percentage for a node.
	CpuUtil float32
	// MemUtil indicates the overall Memory Utilization in percentage for a node.
	RamUtil float32
	// HeapUtil indicates the overall Java Heap Utilization in percentage for a node.
	HeapUtil float32
	// DiskUtil indicates the overall Disk Utilization in percentage for a node.
	DiskUtil float32
	// NumShards Number of shards present on a node.
	NumShards int
}

// This struct will contain the static metrics of the cluster.
type ClusterStatic struct {
	// ClusterName indicates the Cluster name for the OpenSearch cluster.
	ClusterName string `yaml:"cluster_name" validate:"required,isValidName" json:"cluster_name"`
	// IpAddress indicate the master node IP for the OpenSearch cluster.
	IpAddress string `yaml:"ip_address" validate:"required,ip" json:"ip_address"`
	// CloudType indicate the type of the cloud service where the OpenSearch cluster is deployed.
	CloudType string `yaml:"cloud_type" validate:"required,oneof=AWS GCP AZURE" json:"cloud_type"`
	// BaseNodeType indicate the instance type of the node.
	// This parameters depends on the cloud service.
	BaseNodeType string `yaml:"base_node_type" validate:"required" json:"base_node_type"`
	// NumCpusPerNode indicates the number of the CPU core running on a node in a cluster.
	NumCpusPerNode int `yaml:"number_cpus_per_node" validate:"required,min=1" json:"number_cpus_per_node"`
	// RAMPerNodeInGB indicates the RAM size in GB running on a node in a cluster.
	RAMPerNodeInGB int `yaml:"ram_per_node_in_gb" validate:"required,min=1" json:"ram_per_node_in_gb"`
	// DiskPerNodeInGB indicates the Disk size in GB running on a node in a cluster.
	DiskPerNodeInGB int `yaml:"disk_per_node_in_gb" validate:"required,min=1" json:"disk_per_node_in_gb"`
	// NumMaxNodesAllowed indicates the number of maximum allowed node present in the cluster.
	// Based on this value we will determine whether to scale out further or not.
	MaxNodesAllowed int `yaml:"max_nodes_allowed" validate:"required,min=1" json:"max_nodes_allowed"`
	// MinNodesAllowed indicates the number of minimum nodes a cluster should have at any point
	// Based on this value we will determine whether to scale in further or not.
	MinNodesAllowed int `yaml:"min_nodes_allowed" validate:"required,min=1" json:"min_nodes_allowed"`
}

// This struct will contain the dynamic metrics of the cluster.
type ClusterDynamic struct {
	// NumNodes indicates the number of nodes present in the OpenSearch cluster at any time.
	NumNodes int
	//      ClusterStatus indicates the present state of a cluster.
	//      red: One or more primary shards are unassigned, so some data is unavailable.
	//              This can occur briefly during cluster startup as primary shards are assigned.
	//      yellow: All primary shards are assigned, but one or more replica shards are unassigned.
	//              If a node in the cluster fails, some data could be unavailable until that node is repaired.
	//      green: All shards are assigned.
	ClusterStatus string
	// NumActiveShards indicates the total number of active primary and replica shards.
	NumActiveShards int
	// NumActivePrimaryShards indicates the number of active primary shards.
	NumActivePrimaryShards int
	// NumInitializingShards indicates the number of shards that are under initialization.
	NumInitializingShards int
	// NumUnassignedShards indicats the number of shards that are not allocated.
	NumUnassignedShards int
	// NumRelocatingShards indicates the number of shards that are under relocation.
	NumRelocatingShards int
	// NumMasterNodes indicates the number of master eligible nodes present in the cluster.
	NumMasterNodes int
	// NumActiveDataNodes indicates the number of active data nodes present in the cluster.
	NumActiveDataNodes int
}

// This struct will provide the overall cluster metrcis for a OpenSearch cluster.
type Cluster struct {
	// ClusterStatic indicates the static set of data present for a cluster.
	ClusterStatic ClusterStatic
	// ClusterDyanamic indicates the dynamic set of data present for a cluster.
	ClusterDynamic ClusterDynamic
	// NodeList indicates node metrics for all the nodes.
	NodeList []Node
}

// This struct used by the recommendation engine to find the statistics of a metrics for a given period.(CPU, MEM, HEAP, DISK).
type MetricStats struct {
	// Avg indicates the average for a metric for a time period.
	Avg float32
	// Min indicates the minimum value for a metric for a time period.
	Min float32
	// Max indicates the maximum value for a metric for a time period.
	Max float32
}

// This struct contains statistics for a metric on a node for an evaluation period.
type MetricStatsNode struct {
	// MetricStats indicates statistics for a metric on a node.
	MetricStats
	// HostIp indicates the IP Address for a host
	HostIp string
}

// This struct contains statistics for cluster and node for an evaluation period.
type MetricStatsCluster struct {
	// MetricName indicate the metric for which the statistics is calculated for a given period
	MetricName string
	// ClusterLevel indicates statistics for a metric on a cluster for a time period.
	ClusterLevel MetricStats
	// NodeLevel indicates statistics for a metrics on all the nodes.
	NodeLevel []MetricStatsNode
}

// This struct will provide count, number of times a rule is voilated for a metric
type MetricViolatedCount struct {
	// Count indicates number of times the limit is reached calulated for a given period
	ViolatedCount int
}

// This struct will provide count, number of times a rule is voilated for a metric in a node
type MetricViolatedCountNode struct {
	// MetricViolatedCount indicates the violated count for a metric on a node.
	MetricViolatedCount
	// HostIp indicates the IP Address for a host
	HostIp string
}

// This contains the count voilated for cluster and node for an evaluation period.
type MetricViolatedCountCluster struct {
	// MetricName indicate the metric for which the count is calculated for a given period
	MetricName string
	// ClusterLevel indicates the count voilated for a metric on a cluster for a time period.
	ClusterLevel MetricViolatedCount
	// NodeLevel indicates the list of the count voilated for a metric on all the node for a time period.
	NodeLevel []MetricViolatedCountNode
}

// Input:
//		decisionPeriod (int): Time in minutes used to specify the time range for collecting data from Opensearch.
//		pollingInterval (int): Time in seconds which is the interval between each metric is pushed into the index
//
// Description:
//		Generates the query string necessary to check if there is any datapoints between the specified time range
//
//
// Return:
//		(string): Returns the query string which can be passed as OS query api

func dataPointsQuery(decisionPeriod int, pollingInterval int) string {
	dataPointQuery := `{
	  "query": {
	    "bool": {
	      "filter": {
	        "range": {
	          "Timestamp": {
	            "from": "now-` + strconv.Itoa(decisionPeriod) + `m",
	            "include_lower": true,
	            "include_upper": true,
	            "to": "now-` + strconv.Itoa(decisionPeriod) + `m+` + strconv.Itoa(pollingInterval) + `s"
	          }
	        }
	      }
	    }
	  }
	}`

	return dataPointQuery
}

// Input:
//		metricName (string): The metric for which the average is needed.
//		decisionPeriod (int): Time in minutes used to specify the time range for collecting data from Opensearch.
//
// Description:
//		Generates the query string for determining the average of the metric specified.
//
// Return:
//		(string): Returns the query string that can be given as an OS query api parameter.

func getClusterAvgQuery(metricName string, decisionPeriod int) string {
	clusterAvgQueryString := `{
	  "query": {
	    "bool": {
	      "filter": {
	        "range": {
	          "Timestamp": {
	            "from": "now-` + strconv.Itoa(decisionPeriod) + `m",
	            "include_lower": true,
	            "include_upper": true,
	            "to": null
	          }
	        }
	      }
	    }
	  },
	  "aggs": {
	    "` + metricName + `": {
	      "stats": {
	        "field": "` + metricName + `"
	      }
	    }
	  }
	}`
	return clusterAvgQueryString
}

// Input:
//              metricName (string): The metric name for which the Cluster Average will be calculated
//              decisionPeriod (int): The evaluation time over which the Average will be computed
//		pollingInterval (int): Time in seconds which is the interval between each metric is pushed into the index
//		ctx (context.Context): Request-scoped data that transits processes and APIs.
//
// Description:
//
//              GetClusterAvg will utilize an opensearch query to determine the statistic aggregation.
//              The metricName and decisionPeriod will be supplied as inputs for getting stats aggregate.
//              It will populate MetricStatsCluster struct and return it.
//
// Return:
//              (MetricStats, bool, error): Return a populated (MetricStats) struct, a (bool) value indicating whether there were enough data points to find the Stats, and any (errors).

func GetClusterAvg(ctx context.Context, metricName string, decisionPeriod int, pollingInterval int) (MetricStats, bool, error) {
	//Create an object of MetricStatsCluster to populate and return
	var metricStats MetricStats

	var invalidDatapoints bool

	// Check data points
	dataPointsResp, dpErr := osutils.SearchQuery(ctx, []byte(dataPointsQuery(decisionPeriod, pollingInterval)))
	if dpErr != nil {
		log.Error.Println("Can't query for data points!", dpErr)
		return metricStats, invalidDatapoints, dpErr
	}
	defer dataPointsResp.Body.Close()

	var dpRespInterface map[string]interface{}

	decodeErr := json.NewDecoder(dataPointsResp.Body).Decode(&dpRespInterface)
	if decodeErr != nil {
		log.Error.Println("decode Error: ", decodeErr)
		return metricStats, invalidDatapoints, decodeErr
	}

	if int(dpRespInterface["hits"].(map[string]interface{})["total"].(map[string]interface{})["value"].(float64)) == 0 {
		invalidDatapoints = true
		return metricStats, invalidDatapoints, nil
	}

	//Get the query and convert to json
	var jsonQuery = []byte(getClusterAvgQuery(metricName, decisionPeriod))

	//create a search request and pass the query
	searchResp, err := osutils.SearchQuery(ctx, jsonQuery)
	if err != nil {
		log.Error.Println("Cannot fetch cluster average: ", err)
		return metricStats, invalidDatapoints, err
	}
	defer searchResp.Body.Close()
	//Interface to dump the response
	var queryResultInterface map[string]interface{}

	//decode the response into the interface
	decodeErr = json.NewDecoder(searchResp.Body).Decode(&queryResultInterface)
	if decodeErr != nil {
		log.Error.Println("decode Error: ", decodeErr)
		return metricStats, invalidDatapoints, decodeErr
	}

	//Parse the interface and populate the metricStatsCluster
	avg := queryResultInterface["aggregations"].(map[string]interface{})[metricName].(map[string]interface{})["avg"]
	if avg != nil {
		metricStats.Avg = float32(avg.(float64))
	} else {
		log.Warn.Println(metricName, " average is nil!")
	}
	max := queryResultInterface["aggregations"].(map[string]interface{})[metricName].(map[string]interface{})["max"]
	if max != nil {
		metricStats.Max = float32(max.(float64))
	} else {
		log.Warn.Println(metricName, " max is nil!")
	}
	min := queryResultInterface["aggregations"].(map[string]interface{})[metricName].(map[string]interface{})["min"]
	if min != nil {
		metricStats.Min = float32(min.(float64))
	} else {
		log.Warn.Println(metricName, " min is nil!")
	}
	return metricStats, invalidDatapoints, nil
}

// Input:
//		metricName (string): The metric for which the count is needed.
//		decisionPeriod (int): Time in minutes used to specify the time range for collecting data from Opensearch.
//		limit (float32): The limit which needs to checked for the metric if it has been reached
//
// Description:
//		Generates the query string for determining the number of times the limit for the defined measure has been reached.
//
// Return:
//		(string): Returns the query string that can be given as an OS query api parameter.

func getClusterCountQuery(metricName string, decisionPeriod int, limit float32) string {
	clusterCountQueryString := `{
	   "query": {
	     "bool": {
	       "filter": {
	         "range": {
	           "Timestamp": {
	             "from": "now-` + strconv.Itoa(decisionPeriod) + `m",
	             "include_lower": true,
	             "include_upper": true,
	             "to": null
	           }
	         }
	       }
	     }
	   },
	   "aggs": {
	     "` + metricName + `": {
	       "range": {
	         "field": "` + metricName + `",
	         "ranges": [
	           {
	             "from": ` + strconv.FormatFloat(float64(limit), 'E', -1, 32) + `,
	             "to": null
	           }
	         ]
	       }
	     }
	   }
	 }`

	return clusterCountQueryString
}

// Input:
//		metricName (string): The name of the metric that will be used to compute the number of times the limit is reached.
//		decisionPeriod (int): The evaluation period for which the Count will be determined.
//		pollingInterval (int): Time in seconds which is the interval between each metric is pushed into the index
//		limit (float32): The limit for the metric for which the count is calculated.
//		ctx (context.Context): Request-scoped data that transits processes and APIs.
//
// Description:
//		GetClusterCount will return the number of times the specified metric has reached the limit.
//
// Return:
//		(MetricViolatedCount, bool, error): Return populated MetricViolatedCount struct, bool which says if there were enough datapoints to calculate the count and error if any.

func GetClusterCount(ctx context.Context, metricName string, decisionPeriod int, pollingInterval int, limit float32) (MetricViolatedCount, bool, error) {
	var metricViolatedCount MetricViolatedCount
	var invalidDatapoints bool

	// Check data points
	dataPointsResp, dpErr := osutils.SearchQuery(ctx, []byte(dataPointsQuery(decisionPeriod, pollingInterval)))
	if dpErr != nil {
		log.Error.Println("Can't query for data points!", dpErr)
		return metricViolatedCount, invalidDatapoints, dpErr
	}
	defer dataPointsResp.Body.Close()

	var dpRespInterface map[string]interface{}

	decodeErr := json.NewDecoder(dataPointsResp.Body).Decode(&dpRespInterface)
	if decodeErr != nil {
		log.Error.Println("decode Error: ", decodeErr)
		return metricViolatedCount, invalidDatapoints, decodeErr
	}

	if int(dpRespInterface["hits"].(map[string]interface{})["total"].(map[string]interface{})["value"].(float64)) == 0 {
		invalidDatapoints = true
		return metricViolatedCount, invalidDatapoints, nil
	}

	//Get the query and convert to json
	var jsonQuery = []byte(getClusterCountQuery(metricName, decisionPeriod, limit))

	//create a search request and pass the query
	searchResp, err := osutils.SearchQuery(ctx, jsonQuery)
	if err != nil {
		log.Error.Println("Cannot fetch cluster average: ", err)
		return metricViolatedCount, invalidDatapoints, err
	}
	defer searchResp.Body.Close()

	//Interface to dump the response
	var queryResultInterface map[string]interface{}

	//decode the response into the interface
	decodeErr = json.NewDecoder(searchResp.Body).Decode(&queryResultInterface)
	if decodeErr != nil {
		log.Error.Println("decode Error: ", decodeErr)
		return metricViolatedCount, invalidDatapoints, decodeErr
	}
	//Parse the interface and populate the metricStatsCluster
	metricViolatedCount.ViolatedCount = int(queryResultInterface["aggregations"].(map[string]interface{})[metricName].(map[string]interface{})["buckets"].([]interface{})[0].(map[string]interface{})["doc_count"].(float64))

	return metricViolatedCount, invalidDatapoints, nil
}

// Input:
//
// Description:
//		GetClusterCurrent returns the most recent cluster level Statistics and Health in the form of a struct.
//
// Return:
//		(ClusterDynamic): Return populated ClusterDynamic struct.

func GetClusterCurrent() ClusterDynamic {
	ctx := context.Background()
	//Create an interface to capture the response from cluster health and cluster stats API
	var clusterStatsInterface map[string]interface{}
	var clusterHealthInterface map[string]interface{}

	var clusterStats ClusterDynamic

	//Create a cluster stats request and fetch the response
	resp, err := osutils.GetClusterStats(ctx)
	if err != nil {
		log.Error.Println("cluster Stats fetch ERROR:", err)
	}
	defer resp.Body.Close()

	//decode and dump the cluster stats response into interface
	decodeErr := json.NewDecoder(resp.Body).Decode(&clusterStatsInterface)
	if decodeErr != nil {
		log.Error.Println("decode Error: ", decodeErr)
	}

	//Parse the interface and populate required fields in cluster stats
	clusterStats.NumActiveDataNodes = int(clusterStatsInterface["nodes"].(map[string]interface{})["count"].(map[string]interface{})["data"].(float64))
	clusterStats.NumMasterNodes = int(clusterStatsInterface["nodes"].(map[string]interface{})["count"].(map[string]interface{})["master"].(float64))

	//create a cluster health request and fetch cluster health
	clusterHealthRequest, err := osutils.GetClusterHealth(ctx)
	if err != nil {
		log.Error.Println("cluster Health fetch ERROR:", err)
	}
	defer clusterHealthRequest.Body.Close()

	//Decode the response and dump the response into the cluster health interface
	decodeErr2 := json.NewDecoder(clusterHealthRequest.Body).Decode(&clusterHealthInterface)
	if decodeErr2 != nil {
		log.Error.Println("decode Error: ", decodeErr)
	}

	//Parse the interface and populate required fields in cluster stats
	clusterStats.NumNodes = int(clusterHealthInterface["number_of_nodes"].(float64))
	clusterStats.ClusterStatus = clusterStatsInterface["status"].(string)
	clusterStats.NumActiveShards = int(clusterHealthInterface["active_shards"].(float64))
	clusterStats.NumActivePrimaryShards = int(clusterHealthInterface["active_primary_shards"].(float64))
	clusterStats.NumInitializingShards = int(clusterHealthInterface["initializing_shards"].(float64))
	clusterStats.NumUnassignedShards = int(clusterHealthInterface["unassigned_shards"].(float64))
	clusterStats.NumRelocatingShards = int(clusterHealthInterface["relocating_shards"].(float64))

	return clusterStats
}

// Input:
//		decisionPeriod(int): The evaluation period for which the Average will be calculated.(int)
//
// Description:
//		GetClusterHistoricAvg will get Historic average for the cluster for all the metrics.
//		GetClusterHistoricAvg will use the stats aggregation to fetch the cluster and node level
//		Historic average for the mentioned decision period.
//
// Return:
//		([]MetricStatsCluster): Return an array of populated MetricStatsCluster struct collected for all the metrics.

func GetClusterHistoricAvg(decisonPeriod int) []MetricStatsCluster {
	var metricStatsCluster []MetricStatsCluster
	return metricStatsCluster
}

// Input:
//		decisionPeriod(int): The evaluation period for which the Average will be calculated.
//		thresholdMap( map[string]int): The map provide mapping of metric name and the threshold for which the Count is calculated.
//
// Description:
//		GetClusterHistoricCount will use the opensearch query to find out the Count for which a metric crossed the threshold limit.
//		GetClusterHistoricCount will then iterate through all the metric and collect the count for all the metrics.
//		It will return the array of node level and cluster level count been voilated for all the metrics.
//
// Return:
//              ([]MetricViolatedCountCluster): Return array of populated MetricViolatedCountCluster struct.

func GetClusterHistoricCount(decisionPeriod int, thresholdMap map[string]int) []MetricViolatedCountCluster {
	var metricViolatedCount []MetricViolatedCountCluster
	return metricViolatedCount
}
