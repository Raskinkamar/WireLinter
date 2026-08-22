package pack

import (
	"github.com/google/cel-go/cel"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

type SecretSpec struct {
	Env         string `json:"env" yaml:"env"`
	Required    *bool  `json:"required,omitempty" yaml:"required,omitempty"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

type DocSpec struct {
	URL      string `json:"url" yaml:"url"`
	Revision string `json:"revision,omitempty" yaml:"revision,omitempty"`
	Section  string `json:"section,omitempty" yaml:"section,omitempty"`
}

type Manifest struct {
	PackProtocol         string                `json:"packProtocol" yaml:"packProtocol"`
	ID                   string                `json:"id" yaml:"id"`
	Name                 string                `json:"name" yaml:"name"`
	PackVersion          string                `json:"packVersion" yaml:"packVersion"`
	ProviderDocsRevision string                `json:"providerDocsRevision" yaml:"providerDocsRevision"`
	MinWireLinterVersion  string                `json:"minWireLinterVersion,omitempty" yaml:"minWireLinterVersion,omitempty"`
	Capabilities         []string              `json:"capabilities" yaml:"capabilities"`
	Secrets              map[string]SecretSpec `json:"secrets,omitempty" yaml:"secrets,omitempty"`
	Docs                 map[string]DocSpec    `json:"docs" yaml:"docs"`
	Schemas              map[string]string     `json:"schemas,omitempty" yaml:"schemas,omitempty"`
	Signatures           map[string]string     `json:"signatures,omitempty" yaml:"signatures,omitempty"`
	SecretMatches        map[string]string     `json:"secretMatches,omitempty" yaml:"secretMatches,omitempty"`
	DigestMatches        map[string]string     `json:"digestMatches,omitempty" yaml:"digestMatches,omitempty"`
	Rules                []string              `json:"rules" yaml:"rules"`
	Metadata             map[string]any        `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

type Rule struct {
	SchemaVersion    int               `json:"schemaVersion" yaml:"schemaVersion"`
	ID               string            `json:"id" yaml:"id"`
	Kind             string            `json:"kind" yaml:"kind"`
	Scope            string            `json:"scope" yaml:"scope"`
	Severity         string            `json:"severity" yaml:"severity"`
	Stability        string            `json:"stability" yaml:"stability"`
	Title            string            `json:"title" yaml:"title"`
	Explanation      string            `json:"explanation" yaml:"explanation"`
	When             string            `json:"when,omitempty" yaml:"when,omitempty"`
	Requires         string            `json:"requires,omitempty" yaml:"requires,omitempty"`
	Assert           string            `json:"assert,omitempty" yaml:"assert,omitempty"`
	TargetPointer    string            `json:"targetPointer,omitempty" yaml:"targetPointer,omitempty"`
	SchemaRef        string            `json:"schemaRef,omitempty" yaml:"schemaRef,omitempty"`
	SignatureRef     string            `json:"signatureRef,omitempty" yaml:"signatureRef,omitempty"`
	SecretMatchRef   string            `json:"secretMatchRef,omitempty" yaml:"secretMatchRef,omitempty"`
	DigestMatchRef   string            `json:"digestMatchRef,omitempty" yaml:"digestMatchRef,omitempty"`
	DocsRef          string            `json:"docsRef" yaml:"docsRef"`
	RemediationKey   string            `json:"remediationKey,omitempty" yaml:"remediationKey,omitempty"`
	Messages         map[string]string `json:"messages,omitempty" yaml:"messages,omitempty"`
	EvidencePointers []string          `json:"evidencePointers,omitempty" yaml:"evidencePointers,omitempty"`
	Metadata         map[string]any    `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

type CompiledRule struct {
	SourcePath      string
	Rule            Rule
	WhenProgram     cel.Program
	RequiresProgram cel.Program
	AssertProgram   cel.Program
}

type Loaded struct {
	Manifest      Manifest
	Rules         []CompiledRule
	Schemas       map[string]*jsonschema.Schema
	Signatures    map[string]SignatureRecipe
	SecretMatches map[string]SecretMatchRecipe
	DigestMatches map[string]DigestMatchRecipe
}
