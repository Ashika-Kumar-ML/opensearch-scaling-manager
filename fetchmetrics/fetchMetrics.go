package fetchmetrics

import (
	"context"
	"time"

	"github.com/maplelabs/opensearch-scaling-manager/logger"
	utils "github.com/maplelabs/opensearch-scaling-manager/utilities"
)

var ctx = context.Background()

var log = new(logger.LOG)

// Initializing logger module
func init() {
	log.Init("logger")
	log.Info.Println("FetchMetrics module initiated")
}

// Input:
// 		pollingInterval(int): Interval (minutes) at which metrics are fetched and indexed
// Descriptions: 
// 		Fetch metrics will index node level and cluster level(if current node is master) 
// 		parameters to opensearch index and deletes documents that are older than
// 	    72 hours
// Return:
func FetchMetrics(pollingInterval int, purgeAfter int) {
	ticker := time.Tick(time.Duration(pollingInterval) * time.Second)
	for range ticker {
		//check if current node is the master node and update the cluster stats if it is master
		if utils.CheckIfMaster(ctx, "") {
			IndexClusterHealth(ctx)
		}
		//Index the the node stats
		IndexNodeStats(ctx)
		//Purge documents from elasticsearch index that are older than 72 hours
		// DeleteOldDocs(ctx, purgeAfter)
	}
}
