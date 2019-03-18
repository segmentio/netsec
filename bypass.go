package netsec

import "context"

// WithRestrictedNetworkBypass returns a copy of the parent context with the bypass value set.
func WithRestrictedNetworkBypass(ctx context.Context) context.Context {
	return context.WithValue(ctx, bypassRestrictedNetworkKey{}, struct{}{})
}

// HasRestrictedNetworkBypass checks whether or not the context has the value set to bypass
// restricting connections.
func HasRestrictedNetworkBypass(ctx context.Context) bool {
	return ctx.Value(bypassRestrictedNetworkKey{}) != nil
}

type bypassRestrictedNetworkKey struct{}
