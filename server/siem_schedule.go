package server

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/Autumn-27/artex/wazuh"
)

// SIEM setting keys for the analysis schedule.
const (
	siemScheduleKey  = "schedule"
	siemScheduleLast = "schedule-last"
	scheduleTick     = time.Minute
)

// siemSchedule returns the stored schedule, or the default when none is
// stored yet.
func (s *Server) siemSchedule(ctx context.Context) (wazuh.Schedule, error) {
	if s.m.pg == nil {
		return wazuh.DefaultSchedule(), nil
	}
	settings, e := s.m.pg.GetSiemSettings(ctx)
	if e != nil {
		return wazuh.Schedule{}, e
	}
	raw := settings[siemScheduleKey]
	if raw == "" {
		return wazuh.DefaultSchedule(), nil
	}
	sched := wazuh.DefaultSchedule()
	if e = json.Unmarshal([]byte(raw), &sched); e != nil {
		return wazuh.Schedule{}, e
	}
	return sched, nil
}

func (s *Server) scheduleLastRun(ctx context.Context) *time.Time {
	settings, e := s.m.pg.GetSiemSettings(ctx)
	if e != nil {
		return nil
	}
	t, e := time.Parse(time.RFC3339, settings[siemScheduleLast])
	if e != nil {
		return nil
	}
	return &t
}

// runScheduledAnalyses starts a whole-connection run on every enabled
// connection that can read alerts. A connection whose previous scheduled run
// is still going is skipped.
func (s *Server) runScheduledAnalyses(ctx context.Context) int {
	if e := s.m.pg.SetSiemSettings(ctx, map[string]string{siemScheduleLast: time.Now().Format(time.RFC3339)}); e != nil {
		log.Printf("[siem-schedule] record run: %v", e)
	}
	sources, e := s.m.pg.ListWazuhSources(ctx)
	if e != nil {
		log.Printf("[siem-schedule] list sources: %v", e)
		return 0
	}
	started := 0
	for _, source := range sources {
		if !source.Enabled || source.Config.IndexerURL == "" || scheduledRunActive(source.ID) {
			continue
		}
		full, e := s.m.pg.GetWazuhSource(ctx, source.ID)
		if e != nil {
			continue
		}
		auth, e := s.wazuhCredentials(full)
		if e != nil {
			log.Printf("[siem-schedule] %q credentials: %v", full.Name, e)
			continue
		}
		if _, e = s.launchAnalysis(full, auth, "예약 · "+full.Name, nil, "schedule"); e != nil {
			log.Printf("[siem-schedule] %q start: %v", full.Name, e)
			continue
		}
		started++
	}
	return started
}

func scheduledRunActive(sourceID int64) bool {
	analyses.Lock()
	defer analyses.Unlock()
	for _, job := range analyses.jobs {
		if job.source != sourceID {
			continue
		}
		job.mu.Lock()
		active := job.view.Trigger == "schedule" &&
			(job.view.State == "collecting" || job.view.State == "extracting" || job.view.State == "judging")
		job.mu.Unlock()
		if active {
			return true
		}
	}
	return false
}

// scheduleSiemAnalysis checks the schedule once a minute and starts the runs
// that are due.
func (s *Server) scheduleSiemAnalysis(ctx context.Context) {
	ticker := time.NewTicker(scheduleTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if s.m.pg == nil {
			continue
		}
		sched, e := s.siemSchedule(ctx)
		if e != nil {
			log.Printf("[siem-schedule] settings: %v", e)
			continue
		}
		if !sched.Due(s.scheduleLastRun(ctx), time.Now()) {
			continue
		}
		log.Printf("[siem-schedule] due: %d run(s) started", s.runScheduledAnalyses(ctx))
	}
}

func (s *Server) siemScheduleRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/defensive/schedule", s.getSiemSchedule)
	mux.HandleFunc("PUT /api/defensive/schedule", s.putSiemSchedule)
	mux.HandleFunc("POST /api/defensive/schedule/run", s.runSiemScheduleNow)
	mux.HandleFunc("POST /api/defensive/schedule/runner-test", s.testRunner)
}

func (s *Server) scheduleView(ctx context.Context) (map[string]any, error) {
	sched, e := s.siemSchedule(ctx)
	if e != nil {
		return nil, e
	}
	last := s.scheduleLastRun(ctx)
	path, version := runnerStatus()
	out := map[string]any{"schedule": sched, "last_run": last,
		"runner": map[string]any{"available": path != "", "command": runnerCommand, "version": version}}
	if next := sched.Next(last, time.Now()); !next.IsZero() {
		out["next_run"] = next
	}
	return out, nil
}

func (s *Server) getSiemSchedule(w http.ResponseWriter, r *http.Request) {
	if s.pg(w) == nil {
		return
	}
	out, e := s.scheduleView(r.Context())
	if e != nil {
		writeErr(w, 500, "스케줄 설정을 읽지 못했습니다")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, out)
}

func (s *Server) putSiemSchedule(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var in wazuh.Schedule
	if !decodePurpleRequestLimit(w, r, &in, 1<<16) {
		return
	}
	if e := in.Validate(); e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	if !runnerModelRe.MatchString(in.RunnerModel) {
		writeErr(w, 400, "러너 모델 이름을 확인해 주세요")
		return
	}
	raw, _ := json.Marshal(in)
	if e := pg.SetSiemSettings(r.Context(), map[string]string{siemScheduleKey: string(raw)}); e != nil {
		writeErr(w, 500, "스케줄 설정을 저장하지 못했습니다")
		return
	}
	out, e := s.scheduleView(r.Context())
	if e != nil {
		writeErr(w, 500, "스케줄 설정을 읽지 못했습니다")
		return
	}
	writeJSON(w, 200, out)
}

// runSiemScheduleNow starts the scheduled runs immediately; the next run is
// counted from now.
func (s *Server) runSiemScheduleNow(w http.ResponseWriter, r *http.Request) {
	if s.pg(w) == nil {
		return
	}
	started := s.runScheduledAnalyses(context.WithoutCancel(r.Context()))
	if started == 0 {
		writeErr(w, 409, "시작할 수 있는 연결이 없습니다. 연결이 꺼져 있거나 indexer 주소가 없거나 이미 실행 중입니다")
		return
	}
	writeJSON(w, 200, map[string]any{"started": started})
}
