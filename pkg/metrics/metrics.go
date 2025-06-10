package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/ptr"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/sabban/cs-ebpf-bouncer/pkg/xdp"
)

const CollectionInterval = time.Second * 10

type metricName string

const (
	DroppedPackets   metricName = "fw_bouncer_dropped_packets"
	DroppedBytes     metricName = "fw_bouncer_dropped_bytes"
	ProcessedPackets metricName = "fw_bouncer_processed_packets"
	ProcessedBytes   metricName = "fw_bouncer_processed_bytes"
	ActiveBannedIPs  metricName = "fw_bouncer_banned_ips"
)

type metricConfig struct {
	Name         string
	Unit         string
	Gauge        *prometheus.GaugeVec
	LabelKeys    []string
	LastValueMap map[string]float64 // keep last value to send deltas -- nil if absolute
	KeyFunc      func(labels []*io_prometheus_client.LabelPair) string
}

type metricMap map[metricName]*metricConfig

func (m metricMap) MustRegisterAll() {
	for _, met := range m {
		prometheus.MustRegister(met.Gauge)
	}
}

var Map = metricMap{
	ActiveBannedIPs: {
		Name: "active_decisions",
		Unit: "ip",
		Gauge: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: string(ActiveBannedIPs),
			Help: "Denotes the number of IPs which are currently banned",
		}, []string{"origin", "ip_type"}),
		LabelKeys:    []string{"origin", "ip_type"},
		LastValueMap: nil,
		KeyFunc:      func([]*io_prometheus_client.LabelPair) string { return "" },
	},
	DroppedPackets: {
		Name: "dropped",
		Unit: "packet",
		Gauge: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: string(DroppedPackets),
			Help: "Denotes the number of total dropped packets because of rule(s) created by crowdsec",
		}, []string{"origin", "ip_type"}),
		LabelKeys:    []string{"origin", "ip_type"},
		LastValueMap: make(map[string]float64),
		KeyFunc: func(labels []*io_prometheus_client.LabelPair) string {
			return getLabelValue(labels, "origin") + getLabelValue(labels, "ip_type")
		},
	},
	ProcessedPackets: {
		Name: "processed",
		Unit: "packet",
		Gauge: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: string(ProcessedPackets),
			Help: "Denotes the number of total processed packets by the rules created by crowdsec",
		}, []string{"ip_type"}),
		LabelKeys:    []string{"ip_type"},
		LastValueMap: make(map[string]float64),
		KeyFunc: func(labels []*io_prometheus_client.LabelPair) string {
			return getLabelValue(labels, "ip_type")
		},
	},
}

func getLabelValue(labels []*io_prometheus_client.LabelPair, key string) string {
	for _, label := range labels {
		if label.GetName() == key {
			return label.GetValue()
		}
	}

	return ""
}

func MetricsUpdater(met *models.RemediationComponentsMetrics, updateInterval time.Duration) {
	log.Debugf("Updating metrics")

	xdp.CollectMetrics()
	// Most of the common fields are set automatically by the metrics provider
	// We only need to care about the metrics themselves

	promMetrics, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		log.Errorf("unable to gather prometheus metrics: %s", err)
		return
	}

	met.Metrics = append(met.Metrics, &models.DetailedMetrics{
		Meta: &models.MetricsMeta{
			UtcNowTimestamp:   ptr.Of(time.Now().Unix()),
			WindowSizeSeconds: ptr.Of(int64(updateInterval.Seconds())),
		},
		Items: make([]*models.MetricsDetailItem, 0),
	})

	for _, metricFamily := range promMetrics {
		cfg, ok := Map[metricName(metricFamily.GetName())]
		if !ok {
			continue
		}

		for _, metric := range metricFamily.GetMetric() {
			labels := metric.GetLabel()
			value := metric.GetGauge().GetValue()

			labelMap := make(map[string]string)
			for _, key := range cfg.LabelKeys {
				labelMap[key] = getLabelValue(labels, key)
			}

			finalValue := value

			if cfg.LastValueMap == nil {
				// always send absolute values
				log.Debugf("Sending %s for %+v %f", cfg.Name, labelMap, finalValue)
			} else {
				// the final value to send must be relative, and never negative
				// because the firewall counter may have been reset since last collection.
				key := cfg.KeyFunc(labels)

				// no need to guard access to LastValueMap, as we are in the main thread -- it's
				// the gauge that is updated by the requests
				finalValue = value - cfg.LastValueMap[key]

				if finalValue < 0 {
					finalValue = -finalValue

					log.Warningf("metric value for %s %+v is negative, assuming external counter was reset", cfg.Name, labelMap)
				}

				cfg.LastValueMap[key] = value
				log.Debugf("Sending %s for %+v %f | current value: %f | previous value: %f", cfg.Name, labelMap, finalValue, value, cfg.LastValueMap[key])
			}

			met.Metrics[0].Items = append(met.Metrics[0].Items, &models.MetricsDetailItem{
				Name:   ptr.Of(cfg.Name),
				Value:  &finalValue,
				Labels: labelMap,
				Unit:   ptr.Of(cfg.Unit),
			})
		}
	}
}

type StatsDelta struct {
	Processed uint64
	DroppedBy map[string]uint64
}

func CollectAndReset(prev map[uint32]float64) (StatsDelta, map[uint32]uint64, error) {

	delta := StatsDelta{DroppedBy: make(map[string]uint64)}
	curr := make(map[uint32]uint64)          // snapshot we return for next call
	zero := make([]uint64, runtime.NumCPU()) // []uint64{0,0,…} to reset

	it := ipStats.Iterate()
	var (
		key uint32
		val []uint64 // one entry per CPU
	)
	for it.Next(&key, &val) {
		var total uint64
		for _, c := range val {
			total += c
		}

		curr[key] = total

		// compute interval delta
		prevVal := uint64(prev[key])
		if total < prevVal {
			// counter wrapped? shouldn't happen for u64 but guard anyway
			prevVal = 0
		}
		diff := total - prevVal

		switch key {
		case 0:
			delta.Processed = diff
		default:
			name := originName[key]
			if name == "" {
				name = fmt.Sprintf("origin_%d", key)
			}
			delta.DroppedBy[name] += diff
		}

		// reset this counter for *all* CPUs with one Update
		if err := ipStats.Update(key, zero, ebpf.UpdateExist); err != nil {
			return delta, curr, fmt.Errorf("reset key %d: %w", key, err)
		}
	}
	if err := it.Err(); err != nil {
		return delta, curr, err
	}
	return delta, curr, nil
}
