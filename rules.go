package caddy_oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

//go:generate go tool go-enum -f=$GOFILE --marshal

// Action represents the possible actions to take when a rule is matched.
// ENUM(allow, deny)
type Action uint8

// EvaluationResult represents the possible results of ruleset evaluation.
// ENUM(implicit deny, explicit deny, allow)
type EvaluationResult uint8

// RuleEvaluation represents the result of evaluating a ruleset.
type RuleEvaluation struct {
	Result EvaluationResult `json:"result"`
	// The optional ID of the matched rule.
	// If the result is EvaluationResultImplicitDeny, this field is always empty.
	RuleID string `json:"rule_id"`
}

var _ caddy.Provisioner = (*Rule)(nil)
var _ caddyhttp.RequestMatcherWithError = (*Rule)(nil)

// A Rule represents a single authorization rule with an associated action to take when matched with a request.
type Rule struct {
	ID             string               `json:"id,omitempty"`
	Action         Action               `json:"action"`
	MatcherSetsRaw caddy.ModuleMap      `caddy:"namespace=http.matchers" json:"match,omitempty"`
	Matchers       caddyhttp.MatcherSet `json:"-"`
}

// Provision this rule by loading the matcher modules from MatcherSetsRaw.
// Each loaded module must be a RequestMatcher or RequestMatcherWithError.
func (r *Rule) Provision(ctx caddy.Context) error {
	matchersIface, err := ctx.LoadModule(r, "MatcherSetsRaw")
	if err != nil {
		return fmt.Errorf("loading matcher modules: %w", err)
	}

	for _, matcher := range matchersIface.(map[string]any) { //nolint:forcetypeassert
		switch matcher.(type) {
		case caddyhttp.RequestMatcherWithError:
			r.Matchers = append(r.Matchers, matcher)

		//nolint: staticcheck // RequestMatcher deprecated for implementation but kept here for backwards compatibility for parsing
		case caddyhttp.RequestMatcher:
			r.Matchers = append(r.Matchers, matcher)
		default:
			return fmt.Errorf("decoded module is not a RequestMatcher or RequestMatcherWithError: %#v", matcher)
		}
	}

	return nil
}

// MatchWithError returns true if the request matches the rule.
// Unlike caddyhttp.MatcherSets, an empty matcher set never matches a request.
func (r *Rule) MatchWithError(req *http.Request) (bool, error) {
	if len(r.Matchers) == 0 {
		return false, nil
	}

	return r.Matchers.MatchWithError(req)
}

var _ caddyfile.Unmarshaler = (*Ruleset)(nil)
var _ caddy.Provisioner = (*Ruleset)(nil)
var _ caddy.Validator = (*Ruleset)(nil)

// A Ruleset is a set of authorization rules.
type Ruleset []*Rule

func (rules *Ruleset) UnmarshalCaddyfileToken(d *caddyfile.Dispenser) (bool, error) {
	var pol Rule

	switch d.Val() {
	case "allow":
		pol.Action = ActionAllow
	case "deny":
		pol.Action = ActionDeny
	default:
		return false, nil
	}

	// Arguments after the action select one of two forms:
	//   - matcher-set rules (allow <id> { ... }): a block always follows
	//   - role shorthand (allow role1, role2): bare arguments, no block
	args := d.RemainingArgs()

	blockFollows := false
	if d.Next() {
		blockFollows = d.Val() == "{"
		d.Prev()
	}

	if blockFollows || len(args) == 0 {
		// Matcher-set rule: an optional ID, then a matcher block.
		if len(args) > 0 {
			pol.ID = args[0]
		}

		var err error

		pol.MatcherSetsRaw, err = caddyhttp.ParseCaddyfileNestedMatcherSet(d)
		if err != nil {
			return false, err
		}
	} else {
		// Role shorthand: the arguments are role names.
		matcherConfig, err := json.Marshal(MatchRole{Roles: splitRoleArgs(args)})
		if err != nil {
			return false, err
		}

		pol.MatcherSetsRaw = caddy.ModuleMap{"role": matcherConfig}
	}

	*rules = append(*rules, &pol)

	return true, nil
}

// splitRoleArgs splits Caddyfile role arguments on commas, trimming
// surrounding whitespace. It supports both "role1, role2" and "role1 role2".
func splitRoleArgs(args []string) []string {
	var roles []string

	for _, arg := range args {
		for _, part := range strings.Split(arg, ",") {
			if role := strings.TrimSpace(part); role != "" {
				roles = append(roles, role)
			}
		}
	}

	return roles
}

// UnmarshalCaddyfile sets up the Ruleset from Caddyfile tokens.
// Syntax:
//
//	allow|deny <rule_id> {
//		...
//	}
func (rules *Ruleset) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		ok, err := rules.UnmarshalCaddyfileToken(d)
		if err != nil {
			return err
		}

		if !ok {
			return d.Err("expected 'allow' or 'deny'")
		}
	}

	return nil
}

// Provision all rules in the set.
func (rules *Ruleset) Provision(ctx caddy.Context) error {
	for _, p := range *rules {
		err := p.Provision(ctx)
		if err != nil {
			return err
		}
	}

	return nil
}

// ContainsAllow returns true if the set contains at least one ActionAllow rule.
func (rules *Ruleset) ContainsAllow() bool {
	for _, p := range *rules {
		if p.Action == ActionAllow {
			return true
		}
	}

	return false
}

// Validate checks if the set contains at least one ActionAllow rule.
func (rules *Ruleset) Validate() error {
	if !rules.ContainsAllow() {
		return errors.New("no authorization rule is configured to allow access, all requests will be denied without at least one allow rule")
	}

	return nil
}

// Evaluate all rules in the set and return the evaluation result.
// At least one allow rule must match to return EvaluationResultAllow.
// If any "deny" rule is matched, return EvaluationResultExplicitDeny.
func (rules *Ruleset) Evaluate(r *http.Request) (RuleEvaluation, error) {
	eval := RuleEvaluation{
		Result: EvaluationResultImplicitDeny,
	}

	for _, rule := range *rules {
		// Skip allow rule if already accepted.
		if rule.Action == ActionAllow && eval.Result == EvaluationResultAllow {
			continue
		}

		isRuleMatched, err := rule.MatchWithError(r)
		if err != nil {
			return eval, err
		}

		if !isRuleMatched {
			continue
		}

		eval.RuleID = rule.ID

		switch rule.Action {
		case ActionAllow:
			eval.Result = EvaluationResultAllow
		case ActionDeny:
			// Return immediately on deny
			eval.Result = EvaluationResultExplicitDeny

			return eval, nil
		}
	}

	return eval, nil
}
