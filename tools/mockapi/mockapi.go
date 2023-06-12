package main

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"

	"github.com/gorilla/mux"
	json "github.com/json-iterator/go"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"

	"github.com/castai/kvisor/castai"
)

// enforcedRules contains list of rules for policy enforcement.
var enforcedRules = lo.Keys(castai.LinterRuleMap)

func main() {
	router := mux.NewRouter()
	log := logrus.New()

	router.HandleFunc("/v1/security/insights/agent/{cluster_id}/{event}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		clusterID := vars["cluster_id"]
		event := vars["event"]

		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			log.Errorf("gzip reader: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer gz.Close()

		rawBody, err := io.ReadAll(gz)
		if err != nil {
			log.Errorf("read body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		fmt.Printf("received event=%s, cluster_id=%s, body=\n%s\n", event, clusterID, string(rawBody))

		w.WriteHeader(http.StatusAccepted)
	})

	router.HandleFunc("/v1/security/insights/{cluster_id}/log", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		clusterID := vars["cluster_id"]

		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Errorf("read body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		fmt.Printf("received log, cluster_id=%s, body=%s\n", clusterID, string(body))
		w.WriteHeader(http.StatusOK)
	})

	router.HandleFunc("/v1/security/insights/{cluster_id}/telemetry", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		clusterID := vars["cluster_id"]

		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Errorf("read body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		fmt.Printf("received telemetry, cluster_id=%s, body=%s\n", clusterID, string(body))

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(&castai.TelemetryResponse{
			EnforcedRules: enforcedRules,
		}); err != nil {
			log.Errorf("write telemetry response: %v", err)
			return
		}
	})

	if err := http.ListenAndServe(":8090", router); err != nil { //nolint:gosec
		log.Fatal(err)
	}
}
