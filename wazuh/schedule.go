package wazuh

import (
	"errors"
	"fmt"
	"time"
)

// Schedule says when the analysis (collect alerts, extract cases, judge
// them) runs by itself.
type Schedule struct {
	Enabled bool `json:"enabled"`
	// "interval": every IntervalMinutes. "daily": at Times on Weekdays.
	Mode            string `json:"mode"`
	IntervalMinutes int    `json:"interval_minutes"`
	// "HH:MM" in server local time.
	Times []string `json:"times"`
	// 0 = Sunday .. 6 = Saturday. Empty means every day.
	Weekdays []int `json:"weekdays"`
	// Judge new and changed cases right after extraction.
	AutoJudge bool `json:"auto_judge"`
	// Most cases judged in one run; the rest wait for the next run.
	JudgeLimit int `json:"judge_limit"`
	// Send unsure or failed judgments to a debate instead of leaving them.
	Debate bool `json:"debate"`
}

const (
	ScheduleInterval = "interval"
	ScheduleDaily    = "daily"
)

// DefaultSchedule: hourly, judging by itself, debating what it is unsure of.
func DefaultSchedule() Schedule {
	return Schedule{Enabled: true, Mode: ScheduleInterval, IntervalMinutes: 60, Times: []string{"07:30"},
		Weekdays: []int{1, 2, 3, 4, 5}, AutoJudge: true, JudgeLimit: 20, Debate: true}
}

// ErrSchedule: the schedule settings are not usable.
var ErrSchedule = errors.New("스케줄 설정이 올바르지 않습니다")

// Validate checks a schedule and fills nothing in: a bad value is an error.
func (s Schedule) Validate() error {
	switch s.Mode {
	case ScheduleInterval:
		if s.IntervalMinutes < 5 || s.IntervalMinutes > 7*24*60 {
			return fmt.Errorf("%w: 주기는 5분 이상 7일 이하", ErrSchedule)
		}
	case ScheduleDaily:
		if len(s.Times) == 0 || len(s.Times) > 12 {
			return fmt.Errorf("%w: 실행 시각은 1~12개", ErrSchedule)
		}
		for _, t := range s.Times {
			if _, err := time.Parse("15:04", t); err != nil || len(t) != 5 {
				return fmt.Errorf("%w: 시각은 HH:MM 형식 (%q)", ErrSchedule, t)
			}
		}
		seen := map[int]bool{}
		for _, d := range s.Weekdays {
			if d < 0 || d > 6 || seen[d] {
				return fmt.Errorf("%w: 요일은 0(일)~6(토), 중복 없이", ErrSchedule)
			}
			seen[d] = true
		}
	default:
		return fmt.Errorf("%w: 방식은 interval 또는 daily", ErrSchedule)
	}
	if s.JudgeLimit < 1 || s.JudgeLimit > 500 {
		return fmt.Errorf("%w: 실행당 판정 상한은 1~500건", ErrSchedule)
	}
	return nil
}

func (s Schedule) onDay(d time.Weekday) bool {
	if len(s.Weekdays) == 0 {
		return true
	}
	for _, w := range s.Weekdays {
		if w == int(d) {
			return true
		}
	}
	return false
}

// slots returns the daily run times on the calendar day of t, in order.
func (s Schedule) slots(t time.Time) []time.Time {
	if !s.onDay(t.Weekday()) {
		return nil
	}
	out := []time.Time{}
	for _, hm := range s.Times {
		p, err := time.ParseInLocation("15:04", hm, t.Location())
		if err != nil {
			continue
		}
		out = append(out, time.Date(t.Year(), t.Month(), t.Day(), p.Hour(), p.Minute(), 0, 0, t.Location()))
	}
	for i := 1; i < len(out); i++ { // few entries: insertion sort
		for j := i; j > 0 && out[j].Before(out[j-1]); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// Next returns when the schedule next runs after the last run (nil = never
// ran), no earlier than now. The zero time means it never runs.
func (s Schedule) Next(last *time.Time, now time.Time) time.Time {
	if !s.Enabled {
		return time.Time{}
	}
	if s.Mode == ScheduleInterval {
		if last == nil {
			return now
		}
		if next := last.Add(time.Duration(s.IntervalMinutes) * time.Minute); next.After(now) {
			return next
		}
		return now
	}
	// Daily: a slot that passed since the last run is due now (one catch-up
	// run, however many were missed); otherwise the next slot ahead.
	since := now.AddDate(0, 0, -1)
	if last != nil && last.After(since) {
		since = *last
	}
	for day := 0; day <= 8; day++ {
		for _, slot := range s.slots(now.AddDate(0, 0, day-1)) {
			if !slot.After(since) {
				continue
			}
			if slot.After(now) {
				return slot
			}
			return now
		}
	}
	return time.Time{}
}

// Due reports whether a run should start now.
func (s Schedule) Due(last *time.Time, now time.Time) bool {
	next := s.Next(last, now)
	return !next.IsZero() && !next.After(now)
}
