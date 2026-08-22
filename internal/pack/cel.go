package pack

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
)

const (
	maxCELExpressionCodePoints = 8 * 1024
	maxCELExpressionNodes      = 4 * 1024
	maxCELRecursionDepth       = 64
	maxCELComprehensionNesting = 3
	maxCELBindNesting          = 8
	maxCELEvaluationCost       = 100_000
)

type celEnvironments struct {
	envelope *cel.Env
	trace    *cel.Env
}

type celCompiler struct {
	legacy     celEnvironments
	protocol12 celEnvironments
}

func newCELCompiler() (*celCompiler, error) {
	legacy, err := newCELEnvironments(nil)
	if err != nil {
		return nil, err
	}
	protocol12, err := newCELEnvironments([]cel.EnvOption{
		ext.Strings(ext.StringsVersion(5)),
	})
	if err != nil {
		return nil, err
	}
	return &celCompiler{legacy: legacy, protocol12: protocol12}, nil
}

func newCELEnvironments(extra []cel.EnvOption) (celEnvironments, error) {
	common := []cel.EnvOption{
		cel.ParserExpressionSizeLimit(maxCELExpressionCodePoints),
		cel.ExpressionNodeLimit(maxCELExpressionNodes),
		cel.ParserRecursionLimit(maxCELRecursionDepth),
		cel.ASTValidators(
			cel.ValidateComprehensionNestingLimit(maxCELComprehensionNesting),
			cel.ValidateBindNestingLimit(maxCELBindNesting),
			cel.ValidateRegexLiterals(),
		),
		cel.Variable("provider", cel.StringType),
	}
	common = append(common, extra...)

	envelopeOptions := append(append([]cel.EnvOption{}, common...), cel.Variable("envelope", cel.DynType))
	envelope, err := cel.NewEnv(envelopeOptions...)
	if err != nil {
		return celEnvironments{}, fmt.Errorf("create envelope CEL environment: %w", err)
	}
	traceOptions := append(append([]cel.EnvOption{}, common...), cel.Variable("trace", cel.DynType))
	trace, err := cel.NewEnv(traceOptions...)
	if err != nil {
		return celEnvironments{}, fmt.Errorf("create trace CEL environment: %w", err)
	}
	return celEnvironments{envelope: envelope, trace: trace}, nil
}

func (c *celCompiler) compile(protocol, scope, source, purpose string) (cel.Program, error) {
	environments, err := c.environmentsFor(protocol)
	if err != nil {
		return nil, err
	}

	var env *cel.Env
	switch scope {
	case "envelope":
		env = environments.envelope
	case "trace":
		env = environments.trace
	default:
		return nil, fmt.Errorf("unsupported CEL scope %q", scope)
	}

	ast, issues := env.Compile(source)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("compile %s CEL: %w", purpose, issues.Err())
	}
	if !ast.OutputType().IsExactType(cel.BoolType) {
		return nil, fmt.Errorf("%s CEL must return bool, got %s", purpose, ast.OutputType())
	}

	program, err := env.Program(
		ast,
		cel.EvalOptions(cel.OptOptimize),
		cel.CostLimit(maxCELEvaluationCost),
	)
	if err != nil {
		return nil, fmt.Errorf("plan %s CEL: %w", purpose, err)
	}
	return program, nil
}

func (c *celCompiler) environmentsFor(protocol string) (celEnvironments, error) {
	switch protocol {
	case "1.0", "1.1":
		return c.legacy, nil
	case "1.2", "1.3", "1.4":
		return c.protocol12, nil
	default:
		return celEnvironments{}, fmt.Errorf("unsupported pack protocol %q for CEL", protocol)
	}
}
