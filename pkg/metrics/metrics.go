package metrics

import (
	"context"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/klog/v2"
)

type MetricsHelper struct {
	metricsServer *http.Server
	MetricsAddr   string
}

func setupMetricsServer(metricAddress string) *http.Server {
	srv := http.Server{
		Addr: metricAddress,
	}
	srv.Handler = promhttp.Handler()
	return &srv
}

func (p *MetricsHelper) StartMetricsServer(metricsAddr string) {
	p.metricsServer = setupMetricsServer(metricsAddr)

	klog.Infof("started: prometheus metrics server on %s", metricsAddr)

	err := p.metricsServer.ListenAndServe()
	if err != http.ErrServerClosed {
		// Error starting or closing listener
		klog.Errorf("error starting prometheus metrics server: %s", err)
		os.Exit(1)
	}
}

func (p *MetricsHelper) StopMetricsServer() error {
	return p.metricsServer.Shutdown(context.Background())
}

var (
	ID                 = uuid.New().String()
	InboundConnCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "inbound_connection_count",
			Help: "The total number of inbound connections established",
		},
		[]string{"id"},
	)
	OutboundConnCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "outbound_connection_count",
			Help: "The total number of outbound connections established",
		},
		[]string{"id"},
	)
	InboundBytesCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "inbound_bytes_count",
			Help: "The total number of bytes sent and received on inbound connections",
		},
		[]string{"id"},
	)
	OutboundBytesCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "outbound_bytes_count",
			Help: "The total number of bytes sent and received on outbound connections",
		},
		[]string{"id"},
	)
	ActiveInboundConnCount int64 = 0
	ActiveInboundConnGauge       = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "active_inbound_connections",
			Help: "The number of currently active inbound connections",
		},
		[]string{"id"},
	)
	ActiveOutboundConnCount int64 = 0
	ActiveOutboundConnGauge       = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "active_outbound_connections",
			Help: "The number of currently active outbound connections",
		},
		[]string{"id"},
	)
	OutboundConnTimeout = 10 * time.Second
)

func IncrementActiveInboundGauge() {
	InboundConnCounter.WithLabelValues(ID).Inc()
	atomic.AddInt64(&ActiveInboundConnCount, 1)
	ActiveInboundConnGauge.WithLabelValues(ID).Inc()
}

func IncrementActiveOutboundGauge() {
	OutboundConnCounter.WithLabelValues(ID).Inc()
	atomic.AddInt64(&ActiveOutboundConnCount, 1)
	ActiveOutboundConnGauge.WithLabelValues(ID).Inc()
}

func DecrementActiveInboundGauge() {
	atomic.AddInt64(&ActiveInboundConnCount, -1)
	ActiveInboundConnGauge.WithLabelValues(ID).Dec()
}

func DecrementActiveOutboundGauge() {
	atomic.AddInt64(&ActiveOutboundConnCount, -1)
	ActiveOutboundConnGauge.WithLabelValues(ID).Dec()
}

func UpdateBytesReceivedCounter(inboundBytesCopied uint64) {
	InboundBytesCounter.WithLabelValues(ID).Add(float64(inboundBytesCopied))
}
func UpdateBytesSentCounter(outboundBytesCopied uint64) {
	OutboundBytesCounter.WithLabelValues(ID).Add(float64(outboundBytesCopied))
}
