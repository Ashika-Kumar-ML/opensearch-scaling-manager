package fetchmetrics

import (
	"context"
	osutils "github.com/maplelabs/opensearch-scaling-manager/opensearchUtils"
	"strconv"
)

// Input:
//
//	ctx (context.Context): Request-scoped data that transits processes and APIs.
//
// Description:
//
//	Deletes documents that older than 72 hours
//
// Return:
func DeleteOldDocs(ctx context.Context, purgeAfter int) {
	var jsonQuery = []byte(`{
				  "query": {
				    "bool": {
				      "filter": {
				        "range": {
				          "Timestamp": {
				            "lte": "now-` + strconv.Itoa(purgeAfter) + `h"
				          }
				        }
				      }
				    }
				  }
				}`)
	deleteResp, err := osutils.DeleteWithQuery(ctx, jsonQuery)
	if err != nil {
		log.Panic.Println("Unable to execute request: ", err)
		panic(err)
	}
	defer deleteResp.Body.Close()
	log.Info.Println("Document deleted: ", deleteResp)
}
