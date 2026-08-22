package model

import "time"

type Header struct {
	Name     string `json:"name" yaml:"name"`
	Value    string `json:"value" yaml:"value"`
	Redacted bool   `json:"redacted,omitempty" yaml:"redacted,omitempty"`
}

type QueryItem struct {
	Name     string `json:"name" yaml:"name"`
	Value    string `json:"value" yaml:"value"`
	Redacted bool   `json:"redacted,omitempty" yaml:"redacted,omitempty"`
}

type HTTPRequest struct {
	Method              string      `json:"method"`
	URL                 string      `json:"url"`
	Protocol            string      `json:"protocol,omitempty"`
	Headers             []Header    `json:"headers"`
	HeadersCompleteness string      `json:"headersCompleteness"`
	RawQuery            string      `json:"rawQuery"`
	QueryFidelity       string      `json:"queryFidelity"`
	Query               []QueryItem `json:"query,omitempty"`
	BodyFidelity        string      `json:"bodyFidelity"`
	RawBodyBase64       []byte      `json:"rawBodyBase64"`
	BodySHA256          string      `json:"bodySha256,omitempty"`
	DecodedBody         any         `json:"decodedBody,omitempty"`
}

type HTTPResponse struct {
	Status              int      `json:"status"`
	Protocol            string   `json:"protocol,omitempty"`
	Headers             []Header `json:"headers"`
	HeadersCompleteness string   `json:"headersCompleteness"`
	BodyFidelity        string   `json:"bodyFidelity"`
	RawBodyBase64       []byte   `json:"rawBodyBase64"`
	BodySHA256          string   `json:"bodySha256,omitempty"`
	DecodedBody         any      `json:"decodedBody,omitempty"`
	DurationMS          float64  `json:"durationMs"`
}

type Envelope struct {
	ID           string         `json:"id"`
	Provider     string         `json:"provider"`
	Direction    string         `json:"direction,omitempty"`
	EventType    string         `json:"eventType,omitempty"`
	DeliveryID   string         `json:"deliveryId,omitempty"`
	ScenarioStep string         `json:"scenarioStep,omitempty"`
	ReceivedAt   time.Time      `json:"receivedAt"`
	Request      HTTPRequest    `json:"request"`
	Response     *HTTPResponse  `json:"response,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}

type Observation struct {
	ID           string         `json:"id"`
	Type         string         `json:"type"`
	At           time.Time      `json:"at"`
	EnvelopeID   string         `json:"envelopeId,omitempty"`
	ScenarioStep string         `json:"scenarioStep,omitempty"`
	Attributes   map[string]any `json:"attributes,omitempty"`
}

type Trace struct {
	SchemaVersion int            `json:"schemaVersion"`
	TraceID       string         `json:"traceId"`
	Provider      string         `json:"provider"`
	Scenario      string         `json:"scenario,omitempty"`
	StartedAt     time.Time      `json:"startedAt"`
	EndedAt       *time.Time     `json:"endedAt,omitempty"`
	Envelopes     []Envelope     `json:"envelopes"`
	Observations  []Observation  `json:"observations"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

type PackIdentity struct {
	ID                   string `json:"id"`
	Version              string `json:"version"`
	Protocol             string `json:"protocol"`
	ContentDigest        string `json:"contentDigest,omitempty"`
	ProviderDocsRevision string `json:"providerDocsRevision,omitempty"`
}

type EvidenceRef struct {
	TraceID       string `json:"traceId"`
	EnvelopeID    string `json:"envelopeId,omitempty"`
	ObservationID string `json:"observationId,omitempty"`
	JSONPointer   string `json:"jsonPointer"`
	Note          string `json:"note,omitempty"`
}

type DocsRef struct {
	URL      string `json:"url"`
	Revision string `json:"revision,omitempty"`
	Section  string `json:"section,omitempty"`
}

// RuleResult follows SARIF-style result semantics: kind says whether a rule
// passed, failed, could not be decided with available evidence (open), or did
// not apply. Level carries severity only for fail results. MessageID mirrors
// SARIF's message.id concept for stable sub-reasons within one rule.
type RuleResult struct {
	RuleID         string         `json:"ruleId"`
	MessageID      string         `json:"messageId,omitempty"`
	Kind           string         `json:"kind"`
	Level          string         `json:"level"`
	Stability      string         `json:"stability"`
	Provider       string         `json:"provider"`
	Title          string         `json:"title"`
	Message        string         `json:"message"`
	SubjectRef     EvidenceRef    `json:"subjectRef"`
	EvidenceRefs   []EvidenceRef  `json:"evidenceRefs,omitempty"`
	DocsRef        *DocsRef       `json:"docsRef,omitempty"`
	RemediationKey string         `json:"remediationKey,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

type ReportSummary struct {
	Pass          int `json:"pass"`
	Fail          int `json:"fail"`
	Open          int `json:"open"`
	NotApplicable int `json:"notApplicable"`
	Errors        int `json:"errors"`
	Warnings      int `json:"warnings"`
	Notes         int `json:"notes"`
}

type Report struct {
	SchemaVersion int           `json:"schemaVersion"`
	TraceID       string        `json:"traceId"`
	Provider      string        `json:"provider"`
	Pack          *PackIdentity `json:"pack,omitempty"`
	Results       []RuleResult  `json:"results"`
	Summary       ReportSummary `json:"summary"`
}
