// This package includes the methods which fetches the data from simulator
package cluster_sim

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"github.com/maplelabs/opensearch-scaling-manager/cluster"
	"github.com/maplelabs/opensearch-scaling-manager/logger"
	"time"
)

var log logger.LOG

// Input:
//
// Description:
//
//	Initialize the Cluster Simulator module.
//
// Return:
func init() {
	log.Init("logger")
	log.Info.Println("Cluster Simulator module initialized")
}

// Input:
//              metricName (string): The metric name for which the Cluster Average will be calculated
//              decisionPeriod (int): The evaluation time over which the Average will be computed
//
// Description:
//              GetClusterAvg will utilize an opensearch query to determine the statistic aggregation.
//              The metricName and decisionPeriod will be supplied as inputs for getting stats aggregate.
//              It will populate MetricStatsCluster struct and return it.
//
// Return:
//              (cluster.MetricStats, error): Return a populated (MetricStats) struct, and any (errors).

func GetClusterAvg(metricName string, decisionPeriod int, isAccelerated bool) (cluster.MetricStats, error) {
	var metricStats cluster.MetricStats
	var url string
	if isAccelerated {
		t_now := time.Now()
		time_now := fmt.Sprintf("%02d:%02d:%02d", t_now.Hour(), t_now.Minute(), t_now.Second())
		date_now := fmt.Sprintf("%02d-%02d-%d", t_now.Day(), t_now.Month(), t_now.Year())
		url = fmt.Sprintf("http://localhost:5000/stats/avg?metric=%s&duration=%d&time_now=%s%s%s", metricName, decisionPeriod, date_now, "%20", time_now)
	} else {
		url = fmt.Sprintf("http://localhost:5000/stats/avg?metric=%s&duration=%d", metricName, decisionPeriod)
	}

	log.Debug.Println(url)
	client := http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get(url)

	if err != nil {
		log.Panic.Println(err)
		panic(err)
	}

	if resp.StatusCode != 200 {
		response, _ := ioutil.ReadAll(resp.Body)
		return metricStats, errors.New(string(response))
	}

	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&metricStats)
	if err != nil {
		log.Panic.Println(err)
		panic(err)
	}
	log.Debug.Println(metricStats)

	return metricStats, nil
}

// Input:
//              metricName (string): The name of the metric that will be used to compute the number of times the limit is reached.
//              decisionPeriod (int): The evaluation period for which the Count will be determined.
//              limit (float32): The limit for the metric for which the count is calculated.
//
// Description:
//              GetClusterCount will return the number of times the specified metric has reached the limit.
//
// Return:
//              (cluster.MetricViolatedCount, error): Return populated MetricViolatedCount struct and error if any.

func GetClusterCount(metricName string, decisonPeriod int, limit float32, isAccelerated bool) (cluster.MetricViolatedCount, error) {
	var metricViolatedCount cluster.MetricViolatedCount
	var url string
	if isAccelerated {
		t_now := time.Now()
		time_now := fmt.Sprintf("%02d:%02d:%02d", t_now.Hour(), t_now.Minute(), t_now.Second())
		date_now := fmt.Sprintf("%02d-%02d-%d", t_now.Day(), t_now.Month(), t_now.Year())
		url = fmt.Sprintf("http://localhost:5000/stats/violated?metric=%s&duration=%d&threshold=%f&time_now=%s%s%s", metricName, decisonPeriod, limit, date_now, "%20", time_now)
	} else {
		url = fmt.Sprintf("http://localhost:5000/stats/violated?metric=%s&duration=%d&threshold=%f", metricName, decisonPeriod, limit)
	}

	log.Debug.Println(url)
	client := http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(url)

	if err != nil {
		log.Panic.Println(err)
		panic(err)
	}

	if resp.StatusCode != 200 {
		response, _ := ioutil.ReadAll(resp.Body)
		return metricViolatedCount, errors.New(string(response))
	}

	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&metricViolatedCount)

	if err != nil {
		log.Panic.Println(err)
		panic(err)
	}
	log.Debug.Println(metricViolatedCount)
	return metricViolatedCount, nil
}

// Input:
//
// Description:
//              GetClusterCurrent returns the most recent cluster level Statistics and Health in the form of a struct.
//
// Return:
//              (cluster.ClusterDynamic): Return populated ClusterDynamic struct.

func GetClusterCurrent(isAccelerated bool) cluster.ClusterDynamic {
	var clusterStats cluster.ClusterDynamic
	var url string
	if isAccelerated {
		t_now := time.Now()
		time_now := fmt.Sprintf("%02d:%02d:%02d", t_now.Hour(), t_now.Minute(), t_now.Second())
		date_now := fmt.Sprintf("%02d-%02d-%d", t_now.Day(), t_now.Month(), t_now.Year())
		url = fmt.Sprintf("http://localhost:5000/stats/current?time_now=%s%s%s", date_now, "%20", time_now)
	} else {
		url = fmt.Sprintf("http://localhost:5000/stats/current")
	}
	client := http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get(url)
	if err != nil {
		log.Panic.Println(err)
		panic(err)
	}
	defer resp.Body.Close()
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&clusterStats)
	if err != nil {
		log.Panic.Println(err)
		panic(err)
	}
	log.Debug.Println(clusterStats)
	return clusterStats
}
