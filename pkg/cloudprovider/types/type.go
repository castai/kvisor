package types

type Type string

const (
	TypeGCP   Type = "gcp"
	TypeAWS   Type = "aws"
	TypeAzure Type = "azure"
	TypeNone  Type = "none"

	DomainGCP string = "googleapis.com"
	DomainAWS string = "amazonaws.com"
)
