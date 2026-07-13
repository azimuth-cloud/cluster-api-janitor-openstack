package controller

import "github.com/prometheus/client_golang/prometheus"

// Metrics holds the Prometheus counters for the janitor controller.
type Metrics struct {
	CleanupsTotal *prometheus.CounterVec
}

// NewMetrics creates and registers the janitor metrics with reg.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		CleanupsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "capi_janitor",
			Name:      "cleanups_total",
			Help:      "Total number of OpenStack cluster cleanups, labelled by result (success|failure).",
		}, []string{"result"}),
	}
	reg.MustRegister(m.CleanupsTotal)
	return m
}
