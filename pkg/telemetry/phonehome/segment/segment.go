package segment

import (
	segment "github.com/segmentio/analytics-go"
	"github.com/stackrox/rox/pkg/env"
	"github.com/stackrox/rox/pkg/httputil/proxy"
	"github.com/stackrox/rox/pkg/logging"
	"go.uber.org/zap/zapcore"
)

var (
	log = logging.LoggerForModule()
)

// Enabled tells whether telemetry data collection is enabled.
func Enabled() bool {
	return env.TelemetryStorageKey.Setting() != ""
}

type segmentTelemeter struct {
	client   segment.Client
	userID   string
	identity map[string]any
}

// NewTelemeter creates and initializes a Segment telemeter instance.
func NewTelemeter(userID string, identity map[string]any) *segmentTelemeter {
	key := env.TelemetryStorageKey.Setting()
	server := env.TelemetryEndpoint.Setting()
	return initSegment(userID, identity, key, server)
}

type logWrapper struct {
	internal *logging.Logger
}

func (l *logWrapper) Logf(format string, args ...any) {
	l.internal.Logf(zapcore.InfoLevel, format, args...)
}

func (l *logWrapper) Errorf(format string, args ...any) {
	l.internal.Errorf(format, args...)
}

func initSegment(userID string, identity map[string]any, key, server string) *segmentTelemeter {
	segmentConfig := segment.Config{
		Endpoint:  server,
		Interval:  env.TelemetryFrequency.DurationSetting(),
		Transport: proxy.RoundTripper(),
		Logger:    &logWrapper{internal: log},
		DefaultContext: &segment.Context{
			Extra: map[string]any{
				"Central ID": userID,
			},
		},
	}

	client, err := segment.NewWithConfig(key, segmentConfig)
	if err != nil {
		log.Error("Cannot initialize Segment client: ", err)
		return nil
	}

	return &segmentTelemeter{
		client:   client,
		userID:   userID,
		identity: identity,
	}
}

func (t *segmentTelemeter) Start() {
}

func (t *segmentTelemeter) Stop() {
	if t != nil {
		if err := t.client.Close(); err != nil {
			log.Error("Cannot close Segment client: ", err)
		}
	}
}

func (t *segmentTelemeter) GetID() string {
	return t.userID
}

func (t *segmentTelemeter) Identify(props map[string]any) {
	if t == nil {
		return
	}
	traits := segment.NewTraits()
	identity := segment.Identify{
		UserId: t.userID,
		Traits: traits,
	}

	if t.identity != nil {
		for k, v := range t.identity {
			traits.Set(k, v)
		}
	}
	for k, v := range props {
		traits.Set(k, v)
	}
	if err := t.client.Enqueue(identity); err != nil {
		log.Error("Cannot enqueue Segment identity event: ", err)
	}
}

func (t *segmentTelemeter) Group(groupID, userID string, props map[string]any) {
	if t == nil {
		return
	}

	group := segment.Group{
		GroupId: groupID,
		UserId:  userID,
		Traits:  props,
	}

	if err := t.client.Enqueue(group); err != nil {
		log.Error("Cannot enqueue Segment group event: ", err)
	}
}

func (t *segmentTelemeter) Track(event, userID string, props map[string]any) {
	if t == nil {
		return
	}

	track := segment.Track{
		UserId:     userID,
		Event:      event,
		Properties: props,
	}

	if err := t.client.Enqueue(track); err != nil {
		log.Error("Cannot enqueue Segment track event: ", err)
	}
}
