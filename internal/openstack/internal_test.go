/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package openstack

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestIsTransient_NonHTTPStatusError_ReturnsFalse(t *testing.T) {
	if isTransient(errors.New("boom")) {
		t.Error("expected isTransient to return false for a non-httpStatusError")
	}
}

// erroringBody is an io.ReadCloser whose Read always fails, used to simulate
// a network error while streaming a response body.
type erroringBody struct{}

func (erroringBody) Read([]byte) (int, error) { return 0, errors.New("simulated read error") }
func (erroringBody) Close() error             { return nil }

// brokenTransport returns a 200 response with a body that fails to read,
// exercising doGet's io.ReadAll error path.
type brokenTransport struct{}

func (brokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       erroringBody{},
		Header:     make(http.Header),
	}, nil
}

func TestDoGet_ReadBodyError_ReturnsError(t *testing.T) {
	s := &Session{httpClient: &http.Client{Transport: brokenTransport{}}}
	_, err := s.doGet(context.Background(), "http://example.invalid/resource")
	if err == nil {
		t.Fatal("expected error reading response body, got nil")
	}
}
