// This package consists of all the data structure required for defining a task.
// Tasks are set of Actions.
// The actions can have list of rules.
// The recommendation engine will parse these rules and recommend the action if rules meets the criteria.
// Multiple rules can be added inside an action and like wise multiple actions can be added inside a task.
package recommendation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"github.com/maplelabs/opensearch-scaling-manager/cluster"
	"github.com/maplelabs/opensearch-scaling-manager/cluster_sim"
	"github.com/maplelabs/opensearch-scaling-manager/logger"
	"strings"
)

var log logger.LOG
var ctx = context.Background()

// Input:
//
// Description:
//		Initialize the recommendation module.
//
// Return:

func init() {
	log.Init("logger")
	log.Info.Println("Recommendation module initialized")
}

// This struct contains the task to be perforrmed by the recommendation and set of rules wrt the action.
type Task struct {
	// TaskName indicates the name of the task to recommend by the recommendation engine.
	TaskName string `yaml:"task_name" validate:"required,isValidTaskName"`
	// Rules indicates list of rules to evaluate the criteria for the recomm+endation engine.
	Rules []Rule `yaml:"rules" validate:"gt=0,dive"`
	// Operator indicates the logical operation needs to be performed while executing the rules
	Operator string `yaml:"operator" validate:"required,oneof=AND OR"`
}

// This struct contains the rule.
type Rule struct {
	// Metic indicates the name of the metric. These can be:
	//      Cpu
	//      Mem
	//      Shard
	Metric string `yaml:"metric" validate:"required,oneof=CpuUtil RamUtil HeapUtil DiskUtil NumShards"`
	// Limit indicates the threshold value for a metric.
	// If this threshold is achieved for a given metric for the decision periond then the rule will be activated.
	Limit float32 `yaml:"limit" validate:"required"`
	// Stat indicates the statistics on which the evaluation of the rule will happen.
	// For Cpu and Mem the values can be:
	//              Avg: The average CPU or MEM value will be calculated for a given decision period.
	//              Count: The number of occurences where CPU or MEM value crossed the threshold limit.
	//              Term:
	// For rule: Shard, the stat will not be applicable as the shard will be calculated across the cluster and is not a statistical value.
	Stat string `yaml:"stat" validate:"required,oneof=AVG COUNT TERM"`
	// DecisionPeriod indicates the time in minutes for which a rule is evalated.
	DecisionPeriod int `yaml:"decision_period" validate:"required,min=1"`
	// Occurrences indicate the number of time a rule reached the threshold limit for a give decision period.
	// It will be applicable only when the Stat is set to Count.
	Occurrences int `yaml:"occurrences" validate:"required_if=Stat COUNT"`
}

// This struct contains the task details which is set of actions.
type TaskDetails struct {
	// Tasks indicates list of task.
	// A task indicates what operation needs to be recommended by recommendation engine.
	// As of now tasks can be of two types:
	//
	//      scale_up_by_1
	//      scale_down_by_1
	Tasks []Task `yaml:"action" validate:"gt=0,dive"`
}

// Inputs:
//		simFlag (bool): A flag to check if the task needs to be evaluated from Opensearch data or simulated data.
//		pollingInterval (int): Time in seconds which is the interval between each metric is pushed into the index.
//
// Caller:
//		Object of TaskDetails
//
// Description:
//              EvaluateTask will go through all the tasks one by one. and
//              It check if the task are meeting the criteria based on rules and operator.
//              If the task is meeting the criteria then it will push the task to recommendation queue.
//
// Return:
//		([]map[string]string): Returns an array of the recommendations.

func (t TaskDetails) EvaluateTask(pollingInterval int, simFlag, isAccelerated bool) []map[string]string {
	var recommendationArray []map[string]string
	var isRecommendedTask bool
	for _, v := range t.Tasks {
		var rulesResponsibleMap = make(map[string]string)
		isRecommendedTask, rulesResponsibleMap[v.TaskName] = v.GetNextTask(pollingInterval, simFlag, isAccelerated)
		log.Debug.Println(rulesResponsibleMap)
		if isRecommendedTask {
			v.PushToRecommendationQueue()
			recommendationArray = append(recommendationArray, rulesResponsibleMap)
		} else {
			log.Debug.Println(fmt.Sprintf("The %s task is not recommended as rules are not satisfied", v.TaskName))
		}
	}
	return recommendationArray
}

// Inputs:
//		simFlag (bool): A flag to check if the task needs to collect stats from Opensearch data or simulated data.
//		pollingInterval (int): Time in seconds which is the interval between each metric is pushed into the index.
//
// Caller: Object of Task
// Description:
//
//              GetNextTask will get the Task and iterate through all the rules inside the task.
//              Based on the operator it will check if it should iterate through all the rules or not.
//              It will call GetNextRule while iterating through the rules.
//              Based on the result GetNextTask will check if a task can be recommended or not.
//
// Return:
//
//              (bool, string): Return if a task can be recommended or not(bool) and string which says the rules responsible for that recommendation.

func (t Task) GetNextTask(pollingInterval int, simFlag, isAccelerated bool) (bool, string) {
	var isRecommendedTask bool = true
	var isRecommendedRule bool
	var rulesResponsible string
	var err error

	scaleRegexString := `(scale_up|scale_down)_by_([0-9]+)`
	scaleRegex := regexp.MustCompile(scaleRegexString)

	subMatch := scaleRegex.FindStringSubmatch(t.TaskName)

	taskOperation := subMatch[1]

	var rules []string
	for _, v := range t.Rules {
		// Here we can add go routine.
		// So that all the rules getMetrics will be fetched in concurrent way
		// There is a possibility that each rule is taking time.
		// What if in the case of AND the non matching rule is present at the last.
		// What if in the case of OR the matching rule is present at the last.
		isRecommendedRule, err = v.GetNextRule(taskOperation, pollingInterval, simFlag, isAccelerated)
		if err != nil {
			log.Warn.Println(fmt.Sprintf("%s for the rule: %v", err, v))
		}
		if isRecommendedRule {
			if v.Stat == "AVG" {
				rules = append(rules, fmt.Sprintf("%s-%s-%f-%d", v.Metric, v.Stat, v.Limit, v.DecisionPeriod))
			} else {
				rules = append(rules, fmt.Sprintf("%s-%s-%f-%d-%d", v.Metric, v.Stat, v.Limit, v.Occurrences, v.DecisionPeriod))
			}

		}
		if t.Operator == "OR" && isRecommendedRule ||
			t.Operator == "AND" && !isRecommendedRule {
			break
		}
	}
	isRecommendedTask = isRecommendedRule
	if len(rules) > 1 {
		rulesResponsible = strings.Join(rules, "_and_")
	} else if len(rules) == 1 {
		rulesResponsible = rules[0]
	}
	return isRecommendedTask, rulesResponsible
}

// Input:
//		taskOperation (string); Recommended operation
//		simFlag (bool): A flag to check if the task needs to collect stats from Opensearch data or simulated data.
//              pollingInterval (int): Time in seconds which is the interval between each metric is pushed into the index.
//
// Caller:
//		Object of Rule
//
// Description:
//		GetNextRule will fetch the metrics based on the rules MetricName and Stats using GetMetrics
//		Then it will evaluate if the rule is meeting the criteria or not using EvaluateRule
//
// Return:
// 		(bool, error): Return if a rule is meeting the criteria or not(bool) and error if any

func (r Rule) GetNextRule(taskOperation string, pollingInterval int, simFlag, isAccelerated bool) (bool, error) {
	cluster, err := r.GetMetrics(pollingInterval, simFlag, isAccelerated)
	if err != nil {
		return false, err
	}
	isRecommended := r.EvaluateRule(cluster, taskOperation)
	log.Debug.Println(r)
	log.Debug.Println(isRecommended)
	return isRecommended, nil
}

// Input:
//		simFlag (bool): A flag to check if the task needs to collect stats from Opensearch data or simulated data.
//		pollingInterval (int): Time in seconds which is the interval between each metric is pushed into the index.
//
// Caller:
//		Object of Rule
//
// Description:
//              GetMetrics will be getting the metrics for a metricName based on its stats
//              If the stat is Avg then it will call GetClusterAvg which will provide MetricViolatedCountCluster struct.
//              If the stat is Count or Term then it will call GetClusterCount which will provide MetricViolatedCountCluster struct.
//              At last it marshal the structure such that uniform data can be used across multiple methods.
//
// Return:
//              ([]byte, error): Return marshal form of either MetricStatsCluster or MetricViolatedCountCluster struct([]byte) and error if any

func (r Rule) GetMetrics(pollingInterval int, simFlag, isAccelerated bool) ([]byte, error) {
	var clusterStats cluster.MetricStats
	var clusterCount cluster.MetricViolatedCount
	var clusterMetric []byte
	var jsonErr error
	var err error
	var invalidDatapoints bool

	if r.Stat == "AVG" {
		if simFlag {
			clusterStats, err = cluster_sim.GetClusterAvg(r.Metric, r.DecisionPeriod, isAccelerated)
		} else {
			clusterStats, invalidDatapoints, err = cluster.GetClusterAvg(ctx, r.Metric, r.DecisionPeriod, pollingInterval)
		}

		if err != nil || invalidDatapoints {
			if invalidDatapoints {
				err = errors.New("Not enough data points")
			}
			return clusterMetric, err
		}
		clusterMetric, jsonErr = json.MarshalIndent(clusterStats, "", "\t")
		log.Debug.Println(clusterStats)
		if jsonErr != nil {
			log.Panic.Println("Error converting struct to json: ", jsonErr)
			panic(jsonErr)
		}
	} else if r.Stat == "COUNT" || r.Stat == "TERM" {
		if simFlag {
			clusterCount, err = cluster_sim.GetClusterCount(r.Metric, r.DecisionPeriod, r.Limit, isAccelerated)
		} else {
			clusterCount, invalidDatapoints, err = cluster.GetClusterCount(ctx, r.Metric, r.DecisionPeriod, pollingInterval, r.Limit)
		}

		if err != nil || invalidDatapoints {
			if invalidDatapoints {
				err = errors.New("Not enough data points")
			}
			return clusterMetric, err
		}
		clusterMetric, jsonErr = json.MarshalIndent(clusterCount, "", "\t")
		log.Debug.Println(clusterCount)
		if jsonErr != nil {
			log.Panic.Println("Error converting struct to json: ", jsonErr)
			panic(jsonErr)
		}
	}

	return clusterMetric, nil
}

// Input:
//		clusterMetric ([]byte): Marshal struct containing clusterMetric details based on stats.
//		taskOperation (string); Task recommended
//
// Caller:
//		Object of Rule
//
// Description:
//		EvaluateRule will be compare the collected metric and mentioned rule
//		It will then decide if rules are meeting the criteria or not and return the result.
//
// Return:
//              (bool): Return whether a rule is meeting the criteria or not.

func (r Rule) EvaluateRule(clusterMetric []byte, taskOperation string) bool {
	log.Debug.Println(taskOperation)
	if r.Stat == "AVG" {
		var clusterStats cluster.MetricStats
		err := json.Unmarshal(clusterMetric, &clusterStats)
		if err != nil {
			log.Panic.Println("Error converting struct to json: ", err)
			panic(err)
		}
		if taskOperation == "scale_up" && clusterStats.Avg > r.Limit ||
			taskOperation == "scale_down" && clusterStats.Avg < r.Limit {
			return true
		} else {
			return false
		}
	} else if r.Stat == "COUNT" || r.Stat == "TERM" {
		var clusterStats cluster.MetricViolatedCount
		err := json.Unmarshal(clusterMetric, &clusterStats)
		if err != nil {
			log.Panic.Println("Error converting struct to json: ", err)
			panic(err)
		}
		if r.Stat == "COUNT" {
			if taskOperation == "scale_up" && clusterStats.ViolatedCount > r.Occurrences ||
				taskOperation == "scale_down" && clusterStats.ViolatedCount < r.Occurrences {
				return true
			} else {
				return false
			}
		} else if r.Stat == "TERM" {
			if taskOperation == "scale_up" && clusterStats.ViolatedCount > int(r.Limit) ||
				taskOperation == "scale_down" && clusterStats.ViolatedCount < int(r.Limit) {
				return true
			} else {
				return false
			}
		}
	}
	return false
}

// Input:
//
// Caller:
//		Object of Task
// Description:
//		PushToRecommendationQueue will be pushing the task which matches the criteria to recommendation queue.
//
// Return:

func (task Task) PushToRecommendationQueue() {
	log.Info.Println(fmt.Sprintf("The %s task is recommended and will be pushed to the queue", task.TaskName))
}
