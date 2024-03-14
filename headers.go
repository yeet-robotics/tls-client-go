package tls_client

import (
	"net/http"
)

type Headers http.Header

func NewHeaders(headers ...string) *Headers {
	if len(headers)%2 != 0 {
		panic("values must be pairs")
	}

	result := &Headers{}
	for i := 0; i < len(headers); i += 2 {
		result.Set(headers[i], headers[i+1])
	}

	return result
}

func CopyHeaders(headers map[string]string) *Headers {
	result := &Headers{}
	for key, val := range headers {
		result.Set(key, val)
	}
	return result
}

func (h *Headers) Get(name string) []string {
	return (*h)[http.CanonicalHeaderKey(name)]
}

func (h *Headers) Has(name string) bool {
	return len(h.Get(name)) > 0
}

func (h *Headers) GetFirst(name string) (string, bool) {
	if hh := h.Get(name); len(hh) > 0 {
		return hh[0], true
	}

	return "", false
}

func (h *Headers) Set(name string, value string) {
	(*h)[http.CanonicalHeaderKey(name)] = []string{value}
}

func (h *Headers) Remove(name string) {
	delete(*h, http.CanonicalHeaderKey(name))
}

func (h *Headers) SetIfAbsent(name string, value string) {
	if !h.Has(name) {
		(*h)[http.CanonicalHeaderKey(name)] = []string{value}
	}
}

func (h *Headers) CopyFrom(newHeaders *Headers) {
	if newHeaders == nil {
		return
	}

	for name, newValues := range *newHeaders {
		canonicalName := http.CanonicalHeaderKey(name)
		(*h)[canonicalName] = append((*h)[canonicalName], newValues...)
	}
}

func (h *Headers) AddToRequest(req *http.Request, order []string) {
	var headers map[string][]string
	if order != nil {
		headers = make(map[string][]string, len(*h))
		for name, value := range *h {
			headers[name] = value
		}

		// Add headers we know the order of
		for _, name := range order {
			values, ok := headers[name]
			if ok {
				delete(headers, name)
				req.Header[http.CanonicalHeaderKey(name)] = values
			}
		}
	} else {
		headers = *h
	}

	// Add all the other headers
	for name, values := range headers {
		req.Header[http.CanonicalHeaderKey(name)] = values
	}
}
