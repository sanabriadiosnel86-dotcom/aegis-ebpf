// Package k8s resolves the Kubernetes pod a container belongs to, so that the
// agent can enrich audit events with a pod name and namespace.
//
// It talks to the API server directly over HTTP, with the in-cluster
// ServiceAccount credentials, rather than pulling in a large client library.
// It only ever reads (lists pods), in keeping with the read-only posture of
// Aegis-eBPF.
package k8s

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Standard paths of the in-cluster ServiceAccount, mounted by the kubelet.
const (
	tokenPath  = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	caPath     = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	tokenField = "Authorization"
)

// Pod is the identity of the pod that runs a container.
type Pod struct {
	Name      string
	Namespace string
	UID       string
}

// Client is a read-only client for the Kubernetes API server.
type Client struct {
	http    *http.Client
	baseURL string
	token   string
}

// InCluster builds a Client from the ServiceAccount that the kubelet mounts
// into the pod. It fails outside a cluster, where those files and the
// KUBERNETES_SERVICE_* variables are absent.
func InCluster() (*Client, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, fmt.Errorf("k8s: not in a cluster (KUBERNETES_SERVICE_HOST unset)")
	}
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("k8s: reading the ServiceAccount token: %w", err)
	}
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("k8s: reading the cluster CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("k8s: the cluster CA at %s is not valid PEM", caPath)
	}
	return &Client{
		http: &http.Client{
			Timeout:   10 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		},
		baseURL: "https://" + net.JoinHostPort(host, port),
		token:   strings.TrimSpace(string(token)),
	}, nil
}

// podList is the slice of the pod-list response the cache needs.
type podList struct {
	Items []struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
			UID       string `json:"uid"`
		} `json:"metadata"`
		Status struct {
			ContainerStatuses          []containerStatus `json:"containerStatuses"`
			InitContainerStatuses      []containerStatus `json:"initContainerStatuses"`
			EphemeralContainerStatuses []containerStatus `json:"ephemeralContainerStatuses"`
		} `json:"status"`
	} `json:"items"`
}

type containerStatus struct {
	ContainerID string `json:"containerID"`
}

// ListPodsOnNode returns the pods scheduled on nodeName. When nodeName is
// empty it returns every pod the ServiceAccount may read.
func (c *Client) ListPodsOnNode(ctx context.Context, nodeName string) (map[string]Pod, error) {
	u := c.baseURL + "/api/v1/pods?limit=500"
	if nodeName != "" {
		u += "&fieldSelector=" + url.QueryEscape("spec.nodeName="+nodeName)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(tokenField, "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("k8s: listing pods: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("k8s: listing pods: server returned %s", resp.Status)
	}
	var list podList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, fmt.Errorf("k8s: decoding the pod list: %w", err)
	}
	return indexByContainer(&list), nil
}

// indexByContainer maps every container ID of the list to its pod.
func indexByContainer(list *podList) map[string]Pod {
	byID := make(map[string]Pod)
	for i := range list.Items {
		item := &list.Items[i]
		pod := Pod{Name: item.Metadata.Name, Namespace: item.Metadata.Namespace, UID: item.Metadata.UID}
		for _, statuses := range [][]containerStatus{
			item.Status.ContainerStatuses,
			item.Status.InitContainerStatuses,
			item.Status.EphemeralContainerStatuses,
		} {
			for _, cs := range statuses {
				if id := containerHexID(cs.ContainerID); id != "" {
					byID[id] = pod
				}
			}
		}
	}
	return byID
}

// containerHexID extracts the 64-character runtime ID from a Kubernetes
// containerID such as "containerd://<id>" or "docker://<id>".
func containerHexID(containerID string) string {
	_, id, ok := strings.Cut(containerID, "://")
	if !ok || !isHex64(id) {
		return ""
	}
	return id
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, b := range []byte(s) {
		if b < '0' || (b > '9' && b < 'a') || b > 'f' {
			return false
		}
	}
	return true
}

// PodCache keeps a recent map of container ID to pod, refreshed in the
// background so that lookups never block the ingestion path.
type PodCache struct {
	client   *Client
	nodeName string
	log      Logger

	mu    sync.RWMutex
	byID  map[string]Pod
	ready bool
}

// Logger is the subset of *slog.Logger the cache uses; nil disables logging.
type Logger interface {
	Warn(msg string, args ...any)
	Info(msg string, args ...any)
}

// NewPodCache returns a cache that serves lookups for the pods on nodeName.
func NewPodCache(client *Client, nodeName string, log Logger) *PodCache {
	return &PodCache{client: client, nodeName: nodeName, log: log, byID: map[string]Pod{}}
}

// Lookup returns the pod that runs the container, if the cache knows it.
func (c *PodCache) Lookup(containerID string) (Pod, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	pod, ok := c.byID[containerID]
	return pod, ok
}

// Refresh replaces the cache with the current pods on the node.
func (c *PodCache) Refresh(ctx context.Context) error {
	byID, err := c.client.ListPodsOnNode(ctx, c.nodeName)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.byID, c.ready = byID, true
	c.mu.Unlock()
	return nil
}

// Run refreshes the cache immediately and then every interval, until ctx is
// cancelled. It logs failures but keeps serving the last good snapshot.
func (c *PodCache) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := c.Refresh(ctx); err != nil && c.log != nil {
			c.log.Warn("refreshing the pod cache failed", "error", err)
		} else if c.log != nil {
			c.mu.RLock()
			n := len(c.byID)
			c.mu.RUnlock()
			c.log.Info("pod cache refreshed", "containers", n, "node", c.nodeName)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
