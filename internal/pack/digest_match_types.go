package pack

type DigestMatchRecipe struct {
	SchemaVersion int                  `json:"schemaVersion" yaml:"schemaVersion"`
	ID            string               `json:"id" yaml:"id"`
	SourceRefs    []string             `json:"sourceRefs" yaml:"sourceRefs"`
	Secret        DigestMatchSecret    `json:"secret" yaml:"secret"`
	Candidate     DigestMatchCandidate `json:"candidate" yaml:"candidate"`
	Message       []DigestMatchSegment `json:"message" yaml:"message"`
	Hash          DigestMatchHash      `json:"hash" yaml:"hash"`
	Comparison    string               `json:"comparison" yaml:"comparison"`
	Metadata      map[string]any       `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

type DigestMatchSecret struct {
	Ref            string `json:"ref" yaml:"ref"`
	Representation string `json:"representation" yaml:"representation"`
}

type DigestMatchCandidate struct {
	FromHeader DigestMatchHeaderSource `json:"fromHeader" yaml:"fromHeader"`
	Encoding   string                  `json:"encoding" yaml:"encoding"`
}

type DigestMatchHeaderSource struct {
	Name        string `json:"name" yaml:"name"`
	Cardinality string `json:"cardinality" yaml:"cardinality"`
	TrimSpace   bool   `json:"trimSpace,omitempty" yaml:"trimSpace,omitempty"`
}

type DigestMatchSegment struct {
	Secret      bool                      `json:"secret,omitempty" yaml:"secret,omitempty"`
	Literal     *string                   `json:"literal,omitempty" yaml:"literal,omitempty"`
	FromRawBody *DigestMatchRawBodySource `json:"fromRawBody,omitempty" yaml:"fromRawBody,omitempty"`
}

type DigestMatchRawBodySource struct {
	RequireFidelity string `json:"requireFidelity" yaml:"requireFidelity"`
}

type DigestMatchHash struct {
	Algorithm string `json:"algorithm" yaml:"algorithm"`
}
