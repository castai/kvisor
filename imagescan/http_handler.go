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

const (
	ImageDigestHeader = "X-Image-Digest"
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
	if err := h.client.SendImageMetadata(ctx, &md, castai.WithHeader(ImageDigestHeader, md.ImageDigest)); err != nil {
		h.log.Errorf("sending image report: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (h *HTTPHandler) HandleDebugGetImages(w http.ResponseWriter, r *http.Request) {
	type Image struct {
		Key     string
		Name    string
		Arch    string
		Owners  int
		Pods    int
		Nodes   int
		Scanned bool
		ScanErr string
	}

	type Model struct {
		NodesCount  int
		ImagesCount int
		Images      []Image
	}

	model := Model{
		NodesCount:  len(h.ctrl.delta.nodes),
		ImagesCount: len(h.ctrl.delta.images),
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
				Key:     item.key,
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
	
	<div>Nodes: {{.NodesCount}}</div>
	<div>Images: {{.ImagesCount}}</div>
	
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
		  <td><a href="/debug/images/details?key={{.Key}}">{{.Name}}</a></th>
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
		html, body {
			font-family: Verdana,sans-serif;
			font-size: 15px;
			line-height: 1.5;
		}
		a {
			color: #000;
    		text-decoration: none;
		}
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
		th, td, tr {
			padding: 8px;
		}
		table, th, td {
  			border: 1px solid #ccc;
			border-spacing: inherit;
		}
	</style>
`))
	if err := tmpl.Execute(w, model); err != nil {
		h.log.Errorf("debug get images: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func (h *HTTPHandler) HandleDebugGetImage(w http.ResponseWriter, r *http.Request) {
	type Pod struct {
		ID string
	}

	type Node struct {
		Name string
	}

	type Owner struct {
		Pods []Pod
		ID   string
	}

	type Model struct {
		Key    string
		Owners []Owner
		Nodes  []Node
	}

	key := r.URL.Query().Get("key")
	item, found := h.ctrl.delta.images[key]
	if !found {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("image not found, key=" + key))
		return
	}

	model := Model{
		Key: key,
	}
	for key, imgOwner := range item.owners {
		owner := Owner{
			ID: key,
		}
		for podID := range imgOwner.podIDs {
			owner.Pods = append(owner.Pods, Pod{ID: podID})
		}
		model.Owners = append(model.Owners, owner)
	}

	for nodeName := range item.nodes {
		model.Nodes = append(model.Nodes, Node{Name: nodeName})
	}

	tmpl := template.Must(template.New("html").Parse(`
	<h1>Image Details</h1>
	<div>Key: {{.Key}}</div>
	
	<h3>Owners</h3>
	<table>
	  <thead>
		<tr>
		  <th class="text-left">ID</th>
		  <th>Pods</th>
		</tr>
	  </thead>
	  <tbody>
		{{ range .Owners}}
		<tr>
		  <td>{{.ID}}</th>
		  <td>
			{{ range .Pods }}
			<div>{{.ID}}</div>
			{{end}}
          </th>
		</tr>
		{{end}}
	  </tbody>
	</table>

	<h3>Nodes</h3>
	<table>
	  <thead>
		<tr>
		  <th class="text-left">Name</th>
		</tr>
	  </thead>
	  <tbody>
		{{ range .Nodes}}
		<tr>
		  <td>{{.Name}}</th>
		</tr>
		{{end}}
	  </tbody>
	</table>

	<style>
		html, body {
			font-family: Verdana,sans-serif;
			font-size: 15px;
			line-height: 1.5;
		}
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
		th, td, tr {
			padding: 8px;
		}
		table, th, td {
  			border: 1px solid #ccc;
			border-spacing: inherit;
		}
	</style>
`))
	if err := tmpl.Execute(w, model); err != nil {
		h.log.Errorf("debug get images: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}
