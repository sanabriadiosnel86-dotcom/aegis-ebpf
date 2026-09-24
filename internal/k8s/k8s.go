// Package k8s talks to the Kubernetes API server so that the agent can
// resolve the pod a container belongs to and enrich audit events with its
// name and namespace.
//
// It talks to the API server directly over HTTP, with the in-cluster
// ServiceAccount credentials, rather than pulling in a large client library.
// Enrichment only reads (it lists pods), in keeping with the read-only posture
// of Aegis-eBPF. The opt-in decoy responder additionally creates and deletes
// decoy pods through CreatePod and DeletePod; those need their own RBAC and
// are never used unless the agent runs with --decoy.
package k8s

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
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

// CreatedPod is what CreatePod returns: the server-assigned identity of the
// new pod.
type CreatedPod struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	UID       string `json:"uid"`
}

// CreatePod creates a pod in namespace from its JSON manifest and returns its
// server-assigned identity. It is used only by the opt-in decoy responder.
func (c *Client) CreatePod(ctx context.Context, namespace string, manifest []byte) (CreatedPod, error) {
	u := fmt.Sprintf("%s/api/v1/namespaces/%s/pods", c.baseURL, url.PathEscape(namespace))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(manifest))
	if err != nil {
		return CreatedPod{}, err
	}
	req.Header.Set(tokenField, "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return CreatedPod{}, fmt.Errorf("k8s: creating a pod: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return CreatedPod{}, fmt.Errorf("k8s: creating a pod: server returned %s: %s", resp.Status, readError(resp))
	}
	var created struct {
		Metadata CreatedPod `json:"metadata"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return CreatedPod{}, fmt.Errorf("k8s: decoding the created pod: %w", err)
	}
	return created.Metadata, nil
}

// DeletePod deletes a pod. A pod that is already gone is not an error.
func (c *Client) DeletePod(ctx context.Context, namespace, name string) error {
	u := fmt.Sprintf("%s/api/v1/namespaces/%s/pods/%s", c.baseURL, url.PathEscape(namespace), url.PathEscape(name))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set(tokenField, "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("k8s: deleting pod %s/%s: %w", namespace, name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("k8s: deleting pod %s/%s: server returned %s", namespace, name, resp.Status)
	}
	return nil
}

// readError returns the trimmed body of a failed response, for error context.
func readError(resp *http.Response) string {
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<14))
	return strings.TrimSpace(string(msg))
}
