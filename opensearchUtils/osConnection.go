package osutils

import (
	"bytes"
	"context"
	_ "embed"
	"net/http"
	"os"
	"github.com/maplelabs/opensearch-scaling-manager/logger"

	opensearch "github.com/opensearch-project/opensearch-go"
	osapi "github.com/opensearch-project/opensearch-go/opensearchapi"
)

//go:embed mappings.json

var mappingsFile []byte

// Index used by the application
const (
	IndexName string = "monitor-stats"
)

// A global logger variable used across the package for logging.
var log = new(logger.LOG)

// // A global opensearch Client used across the package for Opensearch operations.
var osClient *opensearch.Client

// Input:
//
// Description:
//
//	Initialize the osutils module
//
// Return:
func init() {
	log.Init("logger")
	log.Info.Println("Opensearch module initiated")
}

// Input:
//
//	username (string): Username for OS cluster
//	password (string): Password for OS cluster
//
// Description:
//
//	Initialize the Opensearch client
//
// Return:
func InitializeOsClient(username string, password string) {
	var err error

	osClient, err = opensearch.NewClient(opensearch.Config{
		Addresses: []string{"http://localhost:9200"},
		Username:  username,
		Password:  password,
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
		MaxRetries: 5,
	})
	if err != nil {
		log.Fatal.Println(err)
		os.Exit(1)
	}

	res, err := osClient.Ping()
	if err != nil {
		log.Fatal.Println(err)
		os.Exit(1)
	}

	if res.IsError() {
		log.Fatal.Println("Unable to ping OpenSearch! Error: ", res.Status())
		os.Exit(1)
	}

	log.Info.Println("OpenSearch connection successful: ", res)

	CheckIfIndexExists(context.Background())

}

// Input:
//
//	ctx (context.Context)
//
// Description:
//
//	The function checks if index exists, if it exists it does nothing and returns. If it does not exists, it creates the index and returns
//
// Output:
func CheckIfIndexExists(ctx context.Context) {

	var indexName = []string{IndexName}

	//Create a index exists request to fetch if index is already present or not
	exist, err := osapi.IndicesExistsRequest{
		Index: indexName,
	}.Do(ctx, osClient)
	if err != nil {
		log.Panic.Println("Check index exists request error: ", err)
		panic(err)
	}
	//If status code == 200 then index exists, print index exists, return
	if exist.StatusCode == 200 {
		return
	}
	//If status code is not 200 then index does not exist, so crete a new Index via index create request API,
	// pass mappings and index name.
	indexCreateRequest, err := osapi.IndicesCreateRequest{
		Index: IndexName,
		Body:  bytes.NewReader(mappingsFile),
	}.Do(ctx, osClient)
	if err != nil {
		log.Panic.Println("Index create request error: ", err)
		panic(err)
	}
	log.Info.Println("Created!: ", indexCreateRequest)
}
