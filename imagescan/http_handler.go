package imagescan

import (
	"context"
	"html/template"
	"io"
	"net/http"
	"sort"
	"time"

	json "github.com/json-iterator/go"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"

	"github.com/castai/kvisor/castai"
)

func NewHttpHandlers(log logrus.FieldLogger, client castai.Client, ctrl *Controller) *HTTPHandler {
	return &HTTPHandler{
		log:    log.WithField("component", "scan_http_handler"),
		client: client,
		ctrl:   ctrl,
	}
}

type HTTPHandler struct {
	log    logrus.FieldLogger
	client castai.Client
	ctrl   *Controller
}

// HandleImageMetadata receives image metadata from scan job and sends it to CAST AI platform.
func (h *HTTPHandler) HandleImageMetadata(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		h.log.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	var md castai.ImageMetadata
	if err := json.Unmarshal(data, &md); err != nil {
		h.log.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := h.client.SendImageMetadata(ctx, &md); err != nil {
		h.log.Errorf("sending image report: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (h *HTTPHandler) HandleDebugGetImages(w http.ResponseWriter, r *http.Request) {
	type Image struct {
		Name    string
		Arch    string
		Owners  int
		Pods    int
		Nodes   int
		Scanned bool
		ScanErr string
	}

	type Model struct {
		Images []Image
	}

	model := Model{
		Images: lo.Map(lo.Values(h.ctrl.delta.images), func(item *image, index int) Image {
			var pods int
			for _, owner := range item.owners {
				pods += len(owner.podIDs)
			}
			errStr := ""
			if item.lastScanErr != nil {
				errStr = item.lastScanErr.Error()
			}
			maxErrStr := 200
			if len(errStr) > maxErrStr {
				errStr = errStr[:maxErrStr] + "..."
			}
			return Image{
				Name:    item.name,
				Arch:    item.architecture,
				Owners:  len(item.owners),
				Pods:    pods,
				Nodes:   len(item.nodes),
				Scanned: item.scanned,
				ScanErr: errStr,
			}
		}),
	}
	sort.Slice(model.Images, func(i, j int) bool {
		return model.Images[i].Name < model.Images[j].Name
	})

	tmpl := template.Must(template.New("html").Parse(`
	<h1>Images</h1>
	<table>
	  <thead>
		<tr>
		  <th class="text-left">Name</th>
		  <th>Arch</th>
		  <th>Owners</th>
		  <th>Pods</th>
		  <th>Nodes</th>
		  <th>Scanned</th>
		  <th>Scan Error</th>
		</tr>
	  </thead>
	  <tbody>
		{{ range .Images}}
		<tr>
		  <td>{{.Name}}</th>
		  <td>{{.Arch}}</th>
		  <td class="text-right">{{.Owners}}</th>
		  <td class="text-right">{{.Pods}}</th>
		  <td class="text-right">{{.Nodes}}</th>
		  <td class="scanned-{{.Scanned}}">{{.Scanned}}</th>
		  <td>{{.ScanErr}}</th>
		</tr>
		{{end}}
	  </tbody>
	</table>
	<style>
		.text-left {
			text-align: left;
		}
		.text-right {
			text-align: right;
		}
		.scanned-false {
			color: red;
		}
		.scanned-true {
			color: green;
		}
		td, tr {
			padding: 5px;
		}
	</style>
`))
	if err := tmpl.Execute(w, model); err != nil {
		h.log.Errorf("debug get images: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}
