package castai

type CloudScanReport struct {
	Checks []CloudScanCheck
}

type CloudScanCheck struct {
	ID     string `json:"id"`
	Manual bool   `json:"manual,omitempty"`
	Failed bool   `json:"failed,omitempty"`
}
