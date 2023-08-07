// This file is licensed under the Coder Enterprise License. Please see
// ../LICENSE.enterprise.
package exectracewrapper

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"cdr.dev/slog"
	"cdr.dev/slog/sloggers/slogjson"
)

func TestExectrace(t *testing.T) {
	t.Parallel()

	// This test must be run as root so we can start exectrace.
	if os.Geteuid() != 0 {
		t.Skip("must be run as root")
	}

	currentPidNS, err := getPidNS()
	require.NoError(t, err)

	//nolint:paralleltest // Reserves a port
	t.Run("OK", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		logBuf := bytes.NewBuffer(nil)
		log := slog.Make(slogjson.Sink(logBuf)).Leveled(slog.LevelDebug)

		l := getRandListener(t)
		_ = l.Close()
		addr := l.Addr().String()

		done := make(chan struct{})
		go func() {
			defer close(done)

			err := Run(ctx, log, Options{
				UseLocalPidNS:     false,
				InitListenAddress: addr,
				StartupTimeout:    5 * time.Second,
			})
			assert.Error(t, err)
			assert.ErrorIs(t, err, context.Canceled)
		}()

		// Post the PidNS to the listener.
		require.Eventually(t, func() bool {
			res, err := makeRequest(t, http.MethodPost, "http://"+addr, "text/plain", currentPidNS)
			if err != nil {
				return false
			}
			_ = res.Body.Close()

			return assert.Equal(t, http.StatusNoContent, res.StatusCode)
		}, 5*time.Second, 10*time.Millisecond)

		// Launch a process and wait for it to show up in the logs.
		require.Eventually(t, func() bool {
			const expected = "hello exectrace test 1"
			_, err := exec.CommandContext(ctx, "/bin/sh", "-c", "echo '"+expected+"'").CombinedOutput()
			if !assert.NoError(t, err) {
				return false
			}

			return strings.Contains(logBuf.String(), expected)
		}, 5*time.Second, 100*time.Millisecond)

		cancel()
		<-done
	})

	t.Run("UseCurrentPidNS", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		logBuf := bytes.NewBuffer(nil)
		log := slog.Make(slogjson.Sink(logBuf)).Leveled(slog.LevelDebug)

		done := make(chan struct{})
		go func() {
			defer close(done)

			err := Run(ctx, log, Options{
				UseLocalPidNS:  true,
				StartupTimeout: 5 * time.Second,
			})
			assert.Error(t, err)
			assert.ErrorIs(t, err, context.Canceled)
		}()

		// Launch a process and wait for it to show up in the logs.
		require.Eventually(t, func() bool {
			const expected = "hello exectrace test 2"
			_, err := exec.CommandContext(ctx, "/bin/sh", "-c", "echo '"+expected+"'").CombinedOutput()
			if !assert.NoError(t, err) {
				return false
			}

			return strings.Contains(logBuf.String(), expected)
		}, 5*time.Second, 100*time.Millisecond)

		cancel()
		<-done
	})
}

func TestWaitForExectracePidNS(t *testing.T) {
	t.Parallel()

	t.Run("OK", func(t *testing.T) {
		t.Parallel()
		var (
			ctx = context.Background()
			l   = getRandListener(t)
			uri = (&url.URL{
				Scheme: "http",
				Host:   l.Addr().String(),
				Path:   "/",
			}).String()
			done            = make(chan struct{}, 1)
			expected uint32 = 12345
		)

		go func() {
			defer close(done)
			res, err := makeRequest(t, http.MethodPost, uri, "text/plain", expected)
			assert.NoError(t, err)
			_ = res.Body.Close()
			assert.Equal(t, http.StatusNoContent, res.StatusCode)
			done <- struct{}{}
		}()

		got, err := waitForExectracePidNSListener(ctx, l)
		require.NoError(t, err)

		require.Equal(t, expected, got)

		<-done
	})

	t.Run("BadRequest", func(t *testing.T) {
		t.Parallel()
		var (
			ctx = context.Background()
			l   = getRandListener(t)
			uri = (&url.URL{
				Scheme: "http",
				Host:   l.Addr().String(),
				Path:   "/",
			}).String()
		)

		var (
			expected uint32 = 54321
			done            = make(chan struct{}, 1)
		)
		go func() {
			defer close(done)

			// Bad method.
			res, err := makeRequest(t, http.MethodGet, uri, "", nil)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, res.StatusCode)
			assert.Contains(t, readResBody(t, res), "only accepts POST")

			// Bad path.
			res, err = makeRequest(t, http.MethodPost, uri+"path", "", nil)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, res.StatusCode)
			assert.Contains(t, readResBody(t, res), "only accepts POST requests at /")

			// Bad Content-Type.
			res, err = makeRequest(t, http.MethodPost, uri, "application/json", nil)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, res.StatusCode)
			assert.Contains(t, readResBody(t, res), "only accepts text/plain")

			// No body.
			res, err = makeRequest(t, http.MethodPost, uri, "text/plain", nil)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, res.StatusCode)
			assert.Contains(t, readResBody(t, res), "Failed to parse request body")

			// Invalid uint32.
			res, err = makeRequest(t, http.MethodPost, uri, "text/plain", "yo")
			assert.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, res.StatusCode)
			assert.Contains(t, readResBody(t, res), "Failed to parse request body")

			// Real (with missing CT).
			res, err = makeRequest(t, http.MethodPost, uri, "", expected)
			assert.NoError(t, err)
			_ = res.Body.Close()
			assert.Equal(t, http.StatusNoContent, res.StatusCode)

			// Second post should fail since the server is closed.
			res, err = makeRequest(t, http.MethodPost, uri, "text/plain", expected)
			assert.Error(t, err)
			if err == nil {
				_ = res.Body.Close()
			}
		}()

		got, err := waitForExectracePidNSListener(ctx, l)
		require.NoError(t, err)
		require.Equal(t, expected, got)
		<-done
	})

	t.Run("AlreadyListening", func(t *testing.T) {
		t.Parallel()

		l := getRandListener(t)
		_, err := waitForExectracePidNS(context.Background(), l.Addr().String())
		require.Error(t, err)
		if err != nil {
			require.Contains(t, err.Error(), "address already in use")
		}
	})
}

func getRandListener(t *testing.T) net.Listener {
	l, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err, "listen on available port")
	t.Cleanup(func() {
		_ = l.Close()
	})
	return l
}

func makeRequest(t *testing.T, method, u string, ct string, body any) (*http.Response, error) {
	t.Helper()

	var b io.Reader
	if body != nil {
		switch v := body.(type) {
		case string:
			b = strings.NewReader(v)
		case uint32:
			b = strings.NewReader(strconv.Itoa(int(v)))
		case []byte:
			b = bytes.NewReader(v)
		case io.Reader:
			b = v
		default:
			x, err := json.Marshal(body)
			require.NoError(t, err)
			b = bytes.NewReader(x)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, u, b)
	require.NoError(t, err)

	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}

	return http.DefaultClient.Do(req)
}

func readResBody(t *testing.T, res *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(res.Body)
	assert.NoError(t, err)
	_ = res.Body.Close()

	return string(b)
}
