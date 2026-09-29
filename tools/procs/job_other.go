//go:build !windows

package procs

// Job is a no-op outside Windows; children are killed individually instead.
type Job struct{}

// NewJob returns a no-op job.
func NewJob() (*Job, error) { return &Job{}, nil }

// Assign does nothing.
func (j *Job) Assign(int) error { return nil }

// Close does nothing.
func (j *Job) Close() {}
