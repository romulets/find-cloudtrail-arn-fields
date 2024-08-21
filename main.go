package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/jeremywohl/flatten"
	"golang.org/x/exp/maps"
)

var (
	resourcePattern  *regexp.Regexp = regexp.MustCompile(`^[a-zA-Z]+-([a-zA-Z0-9]{17}|[a-zA-Z0-9]{8})$`)
	jsonArrayPattern *regexp.Regexp = regexp.MustCompile(`\.[0-9]+`)

	awsRegion = "eu-west-1"
)

func main() {
	file, err := os.OpenFile("logs.ndjson", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		slog.Error("Couldn't open log file", slog.String("error", err.Error()))
		return
	}
	defer file.Close()

	slog.SetDefault(slog.New(slog.NewJSONHandler(io.MultiWriter(file, os.Stdout), nil)))
	slog.SetLogLoggerLevel(slog.LevelDebug)

	ctx, cancel := context.WithCancel(context.Background())

	sdkConfig, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		slog.Error("Couldn't load default configuration. Have you set up your AWS account?", slog.String("error", err.Error()))
		return
	}

	cache := make(map[string][]string, 10000)
	eventsCh := make(chan types.Event)
	go startWorker(ctx, eventsCh, cache)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			writeUpSummary(cache)
			os.Exit(0)
		}
	}()

	trailClient := cloudtrail.NewFromConfig(sdkConfig, func(o *cloudtrail.Options) {
		o.Region = awsRegion
	})

	input := &cloudtrail.LookupEventsInput{}

	retry := 0

	for {
		slog.Info("Looking up events", slog.String("next-token", deRef(input.NextToken)))

		out, err := trailClient.LookupEvents(ctx, input)
		if err != nil {
			slog.Error("Couldn't Lookup cloudtrail events", slog.String("error", err.Error()))
			if retry < 3 {
				retry++
				slog.Warn("Retrying request", slog.String("req-token", deRef(input.NextToken)))
				time.Sleep(time.Duration(100^(retry+1)) * time.Millisecond)
				continue
			} else {
				break
			}
		}

		for _, evt := range out.Events {
			eventsCh <- evt
		}

		if out.NextToken == nil {
			break
		}

		input.NextToken = out.NextToken
		retry = 0
	}

	cancel()

	writeUpSummary(cache)
}

func writeUpSummary(cache map[string][]string) {
	file, err := os.OpenFile("summary.csv", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		slog.Error("Couldn't open summary file", slog.String("error", err.Error()))
		return
	}
	defer file.Close()

	wr := csv.NewWriter(file)
	if err := wr.Write([]string{"key", "value", "eventAction", "eventExampleId"}); err != nil {
		slog.Error("Couldn't write csv header", slog.String("error", err.Error()))
		return
	}

	if err := wr.WriteAll(maps.Values(cache)); err != nil {
		slog.Error("Couldn't write all files to csv", slog.String("error", err.Error()))
		return
	}

	wr.Flush()
}

func startWorker(ctx context.Context, eventsCh chan types.Event, cache map[string][]string) {
	slog.Debug("Starting worker")

	for {
		select {
		case <-ctx.Done():
			slog.Debug("Stopping worker")
			return
		case event := <-eventsCh:
			handleEvent(event, cache)
		}
	}
}

func handleEvent(event types.Event, cache map[string][]string) {
	flat, err := flatten.FlattenString(deRef(event.CloudTrailEvent), "", flatten.DotStyle)
	if err != nil {
		slog.Error("Failed to flatten json", slog.String("error", err.Error()), slog.String("event-id", deRef(event.EventId)))
		return
	}

	fields := make(map[string]any, 200)
	if err := json.Unmarshal([]byte(flat), &fields); err != nil {
		slog.Error("Failed to unmarshall flat json", slog.String("error", err.Error()), slog.String("event-id", deRef(event.EventId)))
		return
	}

	for key, value := range fields {
		switch castV := value.(type) {
		case string:
			findIndentifiers(event, key, castV, cache)
		}
	}
}

func findIndentifiers(event types.Event, key, value string, cache map[string][]string) {
	cleanKey := cleanKey(key)

	if _, exists := cache[cleanKey]; exists {
		return
	}

	if strings.HasPrefix(value, "arn:") {
		slog.Info("Has arn",
			slog.String("key", cleanKey),
			slog.String("value", value),
			slog.String("action", deRef(event.EventName)),
			slog.String("event-id", deRef(event.EventId)),
		)

		cache[cleanKey] = []string{cleanKey, value, deRef(event.EventName), deRef(event.EventId)}
		return
	}

	if resourcePattern.Match([]byte(value)) {
		slog.Info("Has resource Id",
			slog.String("key", cleanKey),
			slog.String("value", value),
			slog.String("action", deRef(event.EventName)),
			slog.String("event-id", deRef(event.EventId)),
		)

		cache[cleanKey] = []string{cleanKey, value, deRef(event.EventName), deRef(event.EventId)}
		return
	}
}

func cleanKey(key string) string {
	return string(jsonArrayPattern.ReplaceAll([]byte(key), []byte("[]")))
}

func deRef[T any](ref *T) T {
	if ref == nil {
		var zero T
		return zero
	}

	return *ref
}
