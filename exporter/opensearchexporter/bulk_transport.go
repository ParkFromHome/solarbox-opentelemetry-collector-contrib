// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package opensearchexporter // import "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/opensearchexporter"

import (
	"bytes"
	"io"
	"net/http"
)

// The bulk indexer reuses its buffer as soon as RoundTrip returns. HTTP servers
// may respond before the transport finishes reading a large request body. Give
// the transport its own immutable copy so an early error cannot race with buffer
// reuse or corrupt the next bulk request.
type bulkTransport struct {
	base http.RoundTripper
}

func (t bulkTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Body == nil || request.Body == http.NoBody {
		return t.base.RoundTrip(request)
	}
	// opensearch-go retries EOF even with DisableRetry set, but does not reset
	// Body in that case. Use the request's replayable reader when available so
	// that internal retry cannot send an exhausted body with the original length.
	source := request.Body
	if request.GetBody != nil {
		if err := request.Body.Close(); err != nil {
			return nil, err
		}
		var err error
		source, err = request.GetBody()
		if err != nil {
			return nil, err
		}
	}
	body, err := io.ReadAll(source)
	closeErr := source.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	clone := request.Clone(request.Context())
	clone.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	clone.Body, _ = clone.GetBody()
	return t.base.RoundTrip(clone)
}
