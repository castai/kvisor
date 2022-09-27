package main

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

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

	if err := http.ListenAndServe(":8090", router); err != nil {
		log.Fatal(err)
	}
}
