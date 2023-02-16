package fetchmetrics

import (
	"context"
	"encoding/json"

	"github.com/maplelabs/opensearch-scaling-manager/cluster"
	osutils "github.com/maplelabs/opensearch-scaling-manager/opensearchUtils"
)

// ClusterMetrics holds the cluster level parameters that are to be populated and indexed into opensearch
type ClusterMetrics struct {
	cluster.ClusterDynamic
	Timestamp     int64
	StatTag       string
	_documentType string
	ClusterName   string
}

// Input:
//
//	ctx (context.Context): Request-scoped data that transits processes and APIs.
//
// Description:
//
//	Fetches cluster level info and populates ClusterMetrics struct
//
// Return:
//
//	(ClusterMetrics): Returns cluster metrics struct
func FetchClusterHealthMetrics(ctx context.Context) ClusterMetrics {

	//Create an interface to capture the response from cluster health and cluster stats API
	var clusterStatsInterface map[string]interface{}
	var clusterHealthInterface map[string]interface{}

	clusterStats := new(ClusterMetrics)

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
	clusterStats.Timestamp = int64(clusterStatsInterface["timestamp"].(float64))

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
	clusterStats.StatTag = "ClusterStatistics"
	clusterStats._documentType = "ClusterStatistics"
	clusterStats.ClusterName = clusterHealthInterface["cluster_name"].(string)
	return *clusterStats
}

// Input:
//
//	ctx (context.Context): Request-scoped data that transits processes and APIs.
//
// Description:
//
//	Converts ClusterMetrics struct to Json and indexes it to opensearch
//
// Return:
func IndexClusterHealth(ctx context.Context) {
	var clusterHealth = ClusterMetrics{}

	//fetch the cluster stats
	clusterHealth = FetchClusterHealthMetrics(ctx)

	//Convert the cluster stats struct into Json
	clusterHealthJson, jsonErr := json.MarshalIndent(clusterHealth, "", "\t")
	if jsonErr != nil {
		log.Error.Println("Error converting struct to json: ", jsonErr)
	}

	//Check and index the Json document into opensearch
	resp, err := osutils.IndexMetrics(ctx, clusterHealthJson)
	if err != nil {
		log.Panic.Println("Error indexing cluster document: ", err)
		panic(err)
	}
	defer resp.Body.Close()
	log.Info.Println("Cluster document indexed successfull")
}
