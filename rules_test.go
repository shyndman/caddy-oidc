package caddy_oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/shyndman/caddy-oidc/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuleset_UnmarshalCaddyfile_WithID(t *testing.T) {
	t.Parallel()

	dispenser := caddyfile.NewTestDispenser(`{
		allow s1 {
			path /foo
		}
	}`)

	var ruleset Ruleset

	err := ruleset.UnmarshalCaddyfile(dispenser)
	require.NoError(t, err)

	if assert.Len(t, ruleset, 1) {
		assert.Equal(t, "s1", ruleset[0].ID)
	}
}

func TestRuleset_Evaluate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		session *session.Session
		expect  EvaluationResult
	}{
		{
			name: "empty allow authenticated",
			input: `{
				allow { }
			}`,
			session: &session.Session{
				UID: "test",
			},
			expect: EvaluationResultImplicitDeny,
		},
		{
			name: "deny explicit path match",
			input: `{
				deny {
					path /foo
				}
			}`,
			session: &session.Session{
				UID: "test",
			},
			expect: EvaluationResultExplicitDeny,
		},
		{
			name: "deny explicit user",
			input: `{
				deny {
					user bob@example.com
					user steve@example.com
				}
			}`,
			session: &session.Session{
				UID: "steve@example.com",
			},
			expect: EvaluationResultExplicitDeny,
		},
		{
			name: "deny anonymous at path",
			input: `{
				deny {
					anonymous
					path /foo
				}
			}`,
			session: &session.Session{
				Anonymous: true,
			},
			expect: EvaluationResultExplicitDeny,
		},
		{
			name: "deny anonymous at another path",
			input: `{
				deny {
					anonymous
					path /bar
				}
			}`,
			session: &session.Session{
				Anonymous: true,
			},
			expect: EvaluationResultImplicitDeny,
		},
		{
			name: "deny matching claim",
			input: `{
				deny {
					claim sub steve@example.com
				}
			}`,
			session: &session.Session{
				Claims: json.RawMessage(`{"sub": "steve@example.com"}`),
			},
			expect: EvaluationResultExplicitDeny,
		},
		{
			name: "deny matching claim multiple OR",
			input: `{
				deny {
					claim sub bob@example.com steve@example.com
				}
			}`,
			session: &session.Session{
				Claims: json.RawMessage(`{"sub": "steve@example.com"}`),
			},
			expect: EvaluationResultExplicitDeny,
		},
		{
			name: "deny matching claim multiple AND",
			input: `{
				deny {
					claim role read
					claim role write
				}
			}`,
			session: &session.Session{
				Claims: json.RawMessage(`{"role": ["read": "write"]}`),
			},
			expect: EvaluationResultExplicitDeny,
		},
		{
			name: "deny matching claim wildcard",
			input: `{
				deny {
					claim sub *@example.com
				}
			}`,
			session: &session.Session{
				Claims: json.RawMessage(`{"sub": "steve@example.com"}`),
			},
			expect: EvaluationResultExplicitDeny,
		},
		{
			name: "deny matching claim replacer var",
			input: `{
				deny {
					claim host {http.host}
				}
			}`,
			session: &session.Session{
				Claims: json.RawMessage(`{"host": "example.com"}`),
			},
			expect: EvaluationResultExplicitDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d := caddyfile.NewTestDispenser(tt.input)

			var ruleset Ruleset

			err := ruleset.UnmarshalCaddyfile(d)
			require.NoError(t, err)

			pCtx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})

			err = ruleset.Provision(pCtx)
			require.NoError(t, err)

			r := httptest.NewRequest(http.MethodGet, "/foo?foo=bar", nil)
			r.Header.Set("X-Api-Key", "xyz")
			r.Header.Set("Referer", "https://example.com/page?q=123")
			r = r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{
				caddyhttp.ClientIPVarKey: "127.0.0.1",
			}))

			repl := caddy.NewReplacer()
			repl.Set("http.host", "example.com")

			r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, repl))
			r = r.WithContext(context.WithValue(r.Context(), SessionCtxKey, tt.session))

			e, err := ruleset.Evaluate(r)
			require.NoError(t, err)
			assert.Equalf(t, tt.expect, e.Result, "expected: %s, got: %s", tt.expect, e.Result)
		})
	}
}
