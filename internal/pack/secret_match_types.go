package pack

type SecretMatchRecipe struct {
	SchemaVersion int                  `json:"schemaVersion" yaml:"schemaVersion"`
	ID            string               `json:"id" yaml:"id"`
	SourceRefs    []string             `json:"sourceRefs" yaml:"sourceRefs"`
	Secret        SecretMatchSecret    `json:"secret" yaml:"secret"`
	Candidate     SecretMatchCandidate `json:"candidate" yaml:"candidate"`
	Comparison    string               `json:"comparison" yaml:"comparison"`
	Metadata      map[string]any       `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

type SecretMatchSecret struct {
	Ref            string `json:"ref" yaml:"ref"`
	Representation string `json:"representation" yaml:"representation"`
}

type SecretMatchCandidate struct {
	FromHeader      *SecretMatchHeaderSource      `json:"fromHeader,omitempty" yaml:"fromHeader,omitempty"`
	FromQuery       *SecretMatchQuerySource       `json:"fromQuery,omitempty" yaml:"fromQuery,omitempty"`
	FromDecodedBody *SecretMatchDecodedBodySource `json:"fromDecodedBody,omitempty" yaml:"fromDecodedBody,omitempty"`
}

type SecretMatchHeaderSource struct {
	Name        string `json:"name" yaml:"name"`
	Cardinality string `json:"cardinality" yaml:"cardinality"`
}

type SecretMatchQuerySource struct {
	Name        string `json:"name" yaml:"name"`
	Cardinality string `json:"cardinality" yaml:"cardinality"`
}

type SecretMatchDecodedBodySource struct {
	Path []string `json:"path" yaml:"path"`
}
