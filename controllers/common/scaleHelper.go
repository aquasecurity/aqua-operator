package common

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type ScanQueueJson struct {
	Count    int64               `json:"count"`
	Page     int64               `json:"page"`
	PageSize int64               `json:"pagesize"`
	Result   []map[string]string `json:"result"`
}

func GetPendingScanQueue(username string, password string, server string) (*ScanQueueJson, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s:8080/api/v1/scanqueue?order_by=-created&statuses=pending", server), nil)
	req.SetBasicAuth(username, password)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	var result ScanQueueJson
	body, err := ioutil.ReadAll(resp.Body)
	json.Unmarshal(body, &result)

	return &result, nil
}
