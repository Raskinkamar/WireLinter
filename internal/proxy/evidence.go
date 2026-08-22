package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/Raskinkamar/WireLinter/internal/model"
)

func sanitizeQuery(raw string) (string, []model.QueryItem, string) {
	if raw == "" {
		return "", []model.QueryItem{}, "exact"
	}
	parts := strings.Split(raw, "&")
	items := make([]model.QueryItem, 0, len(parts))
	sanitized := make([]string, 0, len(parts))
	redactedAny := false
	for _, part := range parts {
		nameRaw, valueRaw, found := strings.Cut(part, "=")
		if !found {
			valueRaw = ""
		}
		name, err := url.QueryUnescape(nameRaw)
		if err != nil {
			return "", nil, "unavailable"
		}
		value, err := url.QueryUnescape(valueRaw)
		if err != nil {
			return "", nil, "unavailable"
		}
		item := model.QueryItem{Name: name, Value: value}
		if sensitiveName(name) {
			item.Value = "<redacted>"
			item.Redacted = true
			redactedAny = true
		}
		items = append(items, item)
		if item.Redacted {
			sanitized = append(sanitized, url.QueryEscape(item.Name)+"="+url.QueryEscape(item.Value))
		} else {
			sanitized = append(sanitized, part)
		}
	}
	if !redactedAny {
		return raw, items, "exact"
	}
	return strings.Join(sanitized, "&"), items, "reconstructed"
}

func decodeJSONBody(raw []byte) any {
	if len(raw) == 0 {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil
	}
	return value
}

func semanticRequestHeaders(r *http.Request) []model.Header {
	headers := semanticHeaders(r.Header)
	if r.Host != "" {
		headers = append(headers, model.Header{Name: "Host", Value: r.Host})
	}
	if r.ContentLength > 0 && !containsHeader(headers, "Content-Length") {
		headers = append(headers, model.Header{Name: "Content-Length", Value: strconv.FormatInt(r.ContentLength, 10)})
	}
	if len(r.TransferEncoding) > 0 && !containsHeader(headers, "Transfer-Encoding") {
		headers = append(headers, model.Header{Name: "Transfer-Encoding", Value: strings.Join(r.TransferEncoding, ", ")})
	}
	return headers
}

func semanticResponseHeaders(response *http.Response) []model.Header {
	headers := semanticHeaders(response.Header)
	if response.ContentLength > 0 && !containsHeader(headers, "Content-Length") {
		headers = append(headers, model.Header{Name: "Content-Length", Value: strconv.FormatInt(response.ContentLength, 10)})
	}
	if len(response.TransferEncoding) > 0 && !containsHeader(headers, "Transfer-Encoding") {
		headers = append(headers, model.Header{Name: "Transfer-Encoding", Value: strings.Join(response.TransferEncoding, ", ")})
	}
	return headers
}

func semanticHeaders(header http.Header) []model.Header {
	keys := make([]string, 0, len(header))
	for key := range header {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]model.Header, 0, len(header))
	for _, key := range keys {
		for _, value := range header[key] {
			out = append(out, model.Header{Name: key, Value: value})
		}
	}
	return out
}

func redactHeaders(headers []model.Header) []model.Header {
	out := make([]model.Header, len(headers))
	copy(out, headers)
	for i := range out {
		if !sensitiveName(out[i].Name) {
			continue
		}
		out[i].Value = redactedHeaderValue(out[i].Name, out[i].Value)
		out[i].Redacted = true
	}
	return out
}

func redactedHeaderValue(name, value string) string {
	if strings.EqualFold(strings.TrimSpace(name), "authorization") {
		fields := strings.Fields(value)
		if len(fields) > 0 {
			return fields[0] + " <redacted>"
		}
	}
	return "<redacted>"
}

func sensitiveName(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key", "apikey", "private-token", "access-token", "access_token":
		return true
	}
	return strings.Contains(name, "access_token") ||
		strings.Contains(name, "api-key") ||
		strings.Contains(name, "apikey") ||
		strings.Contains(name, "secret") ||
		strings.HasSuffix(name, "-token") ||
		strings.HasSuffix(name, "_token")
}

func containsHeader(headers []model.Header, name string) bool {
	for _, header := range headers {
		if strings.EqualFold(header.Name, name) {
			return true
		}
	}
	return false
}

func forwardingHeaders(in http.Header) http.Header {
	out := in.Clone()
	removeHopByHopHeaders(out)
	out.Del("Forwarded")
	out.Del("X-Forwarded-For")
	out.Del("X-Forwarded-Host")
	out.Del("X-Forwarded-Proto")
	return out
}

func responseHeadersForSender(in http.Header) http.Header {
	out := in.Clone()
	removeHopByHopHeaders(out)
	return out
}

func removeHopByHopHeaders(header http.Header) {
	for _, connection := range header.Values("Connection") {
		for _, token := range strings.Split(connection, ",") {
			if token = strings.TrimSpace(token); token != "" {
				header.Del(token)
			}
		}
	}
	for _, name := range []string{
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		header.Del(name)
	}
}
