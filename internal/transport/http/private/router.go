// Package private reserves the internal HTTP contour. RBAC currently exposes no private HTTP routes.
package private

import "net/http"

// RegisterRoutes attaches private routes without sharing public or admin handlers.
func RegisterRoutes(_ *http.ServeMux) {}
