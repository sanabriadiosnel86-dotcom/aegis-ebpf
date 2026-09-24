package k8s

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

const (
	webID = "2d1f6c4a9e8b7d0c3f5a6b1e4d7c0a9f8e2b5d6c1a4f7e0b3d9c2a5f8e1b4d7c"
	dbID  = "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0"
)

const podListJSON = `{
  "items": [
    {
      "metadata": {"name": "web-7d9f", "namespace": "shop", "uid": "6c3b1f0e-5d4a-4f2b-9e8d-7c6b5a4f3e2d"},
      "status": {
        "initContainerStatuses": [{"containerID": "containerd://` + dbID + `"}],
        "containerStatuses": [{"containerID": "containerd://` + webID + `"}, {"containerID": ""}]
      }
    },
    {
      "metadata": {"name": "no-status", "namespace": "shop"},
      "status": {}
    }
  ]
}`

func TestContainerHexID(t *testing.T) {
	tests := map[string]string{
		"containerd://" + webID:           webID,
		"docker://" + webID:               webID,
		"cri-o://" + webID:                webID,
		webID:                             "", // no scheme
		"containerd://short":              "",
		"containerd://" + webID + "extra": "",
	}
	for in, want := range tests {
		if got := containerHexID(in); got != want {
			t.Errorf("containerHexID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestListPodsOnNode(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RequestURI()
		if got := r.Header.Get("Authorization"); got != "Bearer sa-token" {
			t.Errorf("Authorization = %q, want the bearer token", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(podListJSON))
	}))
	defer srv.Close()

	client := &Client{http: srv.Client(), baseURL: srv.URL, token: "sa-token"}
	byID, err := client.ListPodsOnNode(context.Background(), "worker-1")
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/v1/pods?limit=500&fieldSelector=spec.nodeName%3Dworker-1" {
		t.Errorf("requested %q, want the node field selector", gotPath)
	}
	web := Pod{Name: "web-7d9f", Namespace: "shop", UID: "6c3b1f0e-5d4a-4f2b-9e8d-7c6b5a4f3e2d"}
	want := map[string]Pod{webID: web, dbID: web}
	if !reflect.DeepEqual(byID, want) {
		t.Errorf("ListPodsOnNode() = %#v, want %#v", byID, want)
	}
}

func TestPodCacheServesLastRefresh(t *testing.T) {
	responses := []string{podListJSON, `{"items":[]}`}
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body := responses[min(n, len(responses)-1)]
		n++
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	cache := NewPodCache(&Client{http: srv.Client(), baseURL: srv.URL, token: "t"}, "worker-1", nil)

	if _, ok := cache.Lookup(webID); ok {
		t.Error("a fresh cache should know no containers")
	}
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if pod, ok := cache.Lookup(webID); !ok || pod.Name != "web-7d9f" {
		t.Errorf("Lookup(web) = %v, %v, want the web pod", pod, ok)
	}
	// A refresh that drops the pod is reflected.
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.Lookup(webID); ok {
		t.Error("Lookup(web) still succeeds after the pod left the node")
	}
}

func TestCreateAndDeletePod(t *testing.T) {
	var method, path, body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		switch r.Method {
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"metadata":{"name":"aegis-decoy-xy12","namespace":"shop","uid":"uid-9"}}`))
		case http.MethodDelete:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"kind":"Status","status":"Success"}`))
		}
	}))
	defer srv.Close()
	client := &Client{http: srv.Client(), baseURL: srv.URL, token: "sa-token"}

	created, err := client.CreatePod(context.Background(), "shop", []byte(`{"kind":"Pod"}`))
	if err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPost || path != "/api/v1/namespaces/shop/pods" {
		t.Errorf("create request = %s %s", method, path)
	}
	if body != `{"kind":"Pod"}` {
		t.Errorf("create body = %q", body)
	}
	if created.Name != "aegis-decoy-xy12" || created.Namespace != "shop" || created.UID != "uid-9" {
		t.Errorf("created = %+v", created)
	}

	if err := client.DeletePod(context.Background(), "shop", "aegis-decoy-xy12"); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodDelete || path != "/api/v1/namespaces/shop/pods/aegis-decoy-xy12" {
		t.Errorf("delete request = %s %s", method, path)
	}
}

func TestDeletePodIgnoresMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	client := &Client{http: srv.Client(), baseURL: srv.URL, token: "t"}
	if err := client.DeletePod(context.Background(), "shop", "gone"); err != nil {
		t.Errorf("deleting a missing pod should be a no-op, got %v", err)
	}
}
