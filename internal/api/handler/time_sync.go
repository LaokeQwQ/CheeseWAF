package handler

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/timekeeper"
)

type TimeSyncService interface {
	Status() timekeeper.Status
	ReselectNow(context.Context) error
	SyncNow(context.Context) error
}

type timeSyncStatusResponse struct {
	Enabled             bool      `json:"enabled"`
	State               string    `json:"state"`
	PrimarySource       string    `json:"primary_source,omitempty"`
	BackupSource        string    `json:"backup_source,omitempty"`
	ActiveSource        string    `json:"active_source,omitempty"`
	OffsetMilliseconds  int64     `json:"offset_ms"`
	RTTMilliseconds     int64     `json:"rtt_ms"`
	Stratum             uint8     `json:"stratum,omitempty"`
	LastSuccess         time.Time `json:"last_success,omitempty"`
	LastAttempt         time.Time `json:"last_attempt,omitempty"`
	ConsecutiveFailures uint64    `json:"consecutive_failures"`
	TotalFailures       uint64    `json:"total_failures"`
	LastError           string    `json:"last_error,omitempty"`
	CurrentTime         time.Time `json:"current_time"`
}

func (h *Handler) TimeSyncStatus(w http.ResponseWriter, _ *http.Request) {
	writeData(w, h.timeSyncStatus())
}

func (h *Handler) ReselectTimeSync(w http.ResponseWriter, r *http.Request) {
	h.runTimeSyncOperation(w, r, true)
}

func (h *Handler) SyncTimeNow(w http.ResponseWriter, r *http.Request) {
	h.runTimeSyncOperation(w, r, false)
}

func (h *Handler) runTimeSyncOperation(w http.ResponseWriter, r *http.Request, reselect bool) {
	if h == nil || h.Config == nil || !h.Config.TimeSync.Enabled {
		writeError(w, http.StatusConflict, "TIME_SYNC_DISABLED", "time synchronization is disabled")
		return
	}
	if h.TimeSync == nil {
		writeError(w, http.StatusServiceUnavailable, "TIME_SYNC_UNAVAILABLE", "time synchronization service is unavailable")
		return
	}
	var err error
	if reselect {
		err = h.TimeSync.ReselectNow(r.Context())
	} else {
		err = h.TimeSync.SyncNow(r.Context())
	}
	if err != nil {
		switch {
		case errors.Is(err, timekeeper.ErrSyncInProgress):
			writeError(w, http.StatusConflict, "TIME_SYNC_BUSY", "time synchronization is already running")
		case errors.Is(err, timekeeper.ErrDisabled):
			writeError(w, http.StatusConflict, "TIME_SYNC_DISABLED", "time synchronization is disabled")
		case errors.Is(err, timekeeper.ErrConfigurationChanged):
			writeError(w, http.StatusConflict, "TIME_SYNC_RECONFIGURED", "time synchronization configuration changed")
		case errors.Is(err, context.DeadlineExceeded):
			writeError(w, http.StatusGatewayTimeout, "TIME_SYNC_TIMEOUT", "time synchronization timed out")
		case errors.Is(err, context.Canceled):
			writeError(w, http.StatusGatewayTimeout, "TIME_SYNC_CANCELED", "time synchronization was canceled")
		default:
			writeError(w, http.StatusBadGateway, "TIME_SYNC_FAILED", "time synchronization did not find a usable source")
		}
		return
	}
	writeData(w, h.timeSyncStatus())
}

func (h *Handler) timeSyncStatus() timeSyncStatusResponse {
	enabled := h != nil && h.Config != nil && h.Config.TimeSync.Enabled
	response := timeSyncStatusResponse{
		Enabled:     enabled,
		State:       "disabled",
		CurrentTime: h.nowUTC(),
	}
	if !enabled {
		return response
	}
	response.State = "local"
	if h.TimeSync == nil {
		response.LastError = "time synchronization service is unavailable"
		return response
	}
	status := h.TimeSync.Status()
	response.PrimarySource = status.Primary
	response.BackupSource = status.Backup
	response.ActiveSource = status.ActiveSource
	response.OffsetMilliseconds = status.Offset.Milliseconds()
	response.RTTMilliseconds = status.RTT.Milliseconds()
	response.Stratum = status.Stratum
	response.LastSuccess = status.LastSuccess
	response.LastAttempt = status.LastAttempt
	response.ConsecutiveFailures = status.ConsecutiveFailures
	response.TotalFailures = status.TotalFailures
	response.LastError = status.LastError
	switch {
	case status.Syncing:
		response.State = "synchronizing"
	case status.Synchronized && !status.LocalFallback:
		response.State = "synchronized"
	default:
		response.State = "local"
	}
	return response
}

var _ TimeSyncService = (*timekeeper.Service)(nil)
