/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// Package nativesso exposes the HTTP surface of OpenID Connect Native SSO for Mobile Apps 1.0 that
// sits outside the OAuth token endpoint: ending an SSO session for every app of a vendor at once.
package nativesso

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/thunder-id/thunderid/pkg/thunderidengine/common"

	applog "github.com/mosip/esignet/internal/log"
)

// LogoutPath ends the SSO session a device secret belongs to.
const LogoutPath = "/native-sso/logout"

// SessionEnder ends the SSO session of a device secret and returns the apps that had joined it.
type SessionEnder interface {
	EndSession(ctx context.Context, deviceSecret string) ([]string, *common.ServiceError)
}

// Handler serves the Native SSO session endpoints.
type Handler struct {
	sessions SessionEnder
	logger   *applog.Logger
}

// NewHandler returns a Handler backed by sessions.
func NewHandler(sessions SessionEnder, logger *applog.Logger) *Handler {
	return &Handler{sessions: sessions, logger: logger}
}

// RegisterRoutes mounts the Native SSO session endpoints on mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST "+LogoutPath, h.logout)
}

type logoutResponse struct {
	Status           string   `json:"status"`
	SignedOutClients []string `json:"signed_out_clients"`
}

type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// logout ends the SSO session identified by the device_secret form parameter. Possession of the
// device secret is the proof of authority: it never leaves the device it was issued to.
func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request"})
		return
	}
	deviceSecret := r.PostForm.Get("device_secret")
	if deviceSecret == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{
			Error: "invalid_request", ErrorDescription: "device_secret is required",
		})
		return
	}

	clients, svcErr := h.sessions.EndSession(r.Context(), deviceSecret)
	if svcErr != nil {
		if svcErr.Type == common.ClientErrorType {
			writeJSON(w, http.StatusBadRequest, errorResponse{
				Error: "invalid_grant", ErrorDescription: svcErr.ErrorDescription.DefaultValue,
			})
			return
		}
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "server_error"})
		return
	}
	writeJSON(w, http.StatusOK, logoutResponse{Status: "logged_out", SignedOutClients: clients})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
