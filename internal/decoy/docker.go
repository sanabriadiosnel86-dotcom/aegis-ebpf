package decoy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// dockerClient is a small client for the Docker Engine API over its unix
// socket. It implements only the calls the decoy needs, so that the agent
// does not depend on the full Docker client library.
type dockerClient struct {
	http *http.Client
}

// newDockerClient dials the Docker socket and verifies the daemon answers.
func newDockerClient(socket string) (*dockerClient, error) {
	c := &dockerClient{
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", socket)
				},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.ping(ctx); err != nil {
		return nil, fmt.Errorf("docker: %s not reachable: %w", socket, err)
	}
	return c, nil
}

func (c *dockerClient) ping(ctx context.Context) error {
	resp, err := c.do(ctx, http.MethodGet, "/_ping", nil)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// containerInfo is the slice of a container inspection the decoy reads.
type containerInfo struct {
	Name            string `json:"Name"`
	NetworkSettings struct {
		Networks map[string]struct {
			NetworkID string `json:"NetworkID"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

// inspect returns the container's details, notably the networks it is on.
func (c *dockerClient) inspect(ctx context.Context, id string) (*containerInfo, error) {
	resp, err := c.do(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/json", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := errorFrom(resp); err != nil {
		return nil, err
	}
	var info containerInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}
	return &info, nil
}

// createRequest is the body of POST /containers/create.
type createRequest struct {
	Image      string            `json:"Image"`
	Cmd        []string          `json:"Cmd"`
	Labels     map[string]string `json:"Labels"`
	HostConfig hostConfig        `json:"HostConfig"`
}

type hostConfig struct {
	NetworkMode string `json:"NetworkMode,omitempty"`
	Memory      int64  `json:"Memory,omitempty"`
	PidsLimit   int64  `json:"PidsLimit,omitempty"`
	// CapDrop drops Linux capabilities; the decoy needs none.
	CapDrop []string `json:"CapDrop,omitempty"`
	// SecurityOpt hardens the decoy: it must not gain privileges.
	SecurityOpt []string `json:"SecurityOpt,omitempty"`
}

// create creates a container and returns its ID, pulling the image once if
// the daemon does not have it.
func (c *dockerClient) create(ctx context.Context, name string, req createRequest) (string, error) {
	id, err := c.createOnce(ctx, name, req)
	if isNoSuchImage(err) {
		if perr := c.pull(ctx, req.Image); perr != nil {
			return "", perr
		}
		id, err = c.createOnce(ctx, name, req)
	}
	return id, err
}

func (c *dockerClient) createOnce(ctx context.Context, name string, req createRequest) (string, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	resp, err := c.do(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(name), body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if err := errorFrom(resp); err != nil {
		return "", err
	}
	var created struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return "", err
	}
	return created.ID, nil
}

// pull fetches an image and waits for the transfer to finish.
func (c *dockerClient) pull(ctx context.Context, image string) error {
	name, tag := splitImage(image)
	q := url.Values{"fromImage": {name}, "tag": {tag}}
	resp, err := c.do(ctx, http.MethodPost, "/images/create?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := errorFrom(resp); err != nil {
		return err
	}
	// The daemon streams progress; draining the body waits for completion.
	_, err = io.Copy(io.Discard, resp.Body)
	return err
}

// start starts a created container.
func (c *dockerClient) start(ctx context.Context, id string) error {
	resp, err := c.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/start", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return errorFrom(resp)
}

// remove force-removes a container; a missing container is not an error.
func (c *dockerClient) remove(ctx context.Context, id string) error {
	resp, err := c.do(ctx, http.MethodDelete, "/containers/"+url.PathEscape(id)+"?force=true", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	return errorFrom(resp)
}

func (c *dockerClient) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	// The host is ignored for a unix socket, but the URL needs one.
	req, err := http.NewRequestWithContext(ctx, method, "http://docker"+path, r)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.http.Do(req)
}

// dockerError is the daemon's JSON error body.
type dockerError struct {
	Status  int
	Message string `json:"message"`
}

func (e *dockerError) Error() string {
	return fmt.Sprintf("docker: %d: %s", e.Status, e.Message)
}

// errorFrom turns a non-2xx response into a *dockerError, consuming the body.
func errorFrom(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	derr := &dockerError{Status: resp.StatusCode, Message: strings.TrimSpace(string(msg))}
	var parsed struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(msg, &parsed) == nil && parsed.Message != "" {
		derr.Message = parsed.Message
	}
	return derr
}

func isNoSuchImage(err error) bool {
	var derr *dockerError
	if !errors.As(err, &derr) {
		return false
	}
	return derr.Status == http.StatusNotFound && strings.Contains(strings.ToLower(derr.Message), "no such image")
}

// splitImage splits "repo/name:tag" into its name and tag, defaulting the tag
// to "latest". A digest (…@sha256:…) is treated as part of the name.
func splitImage(image string) (name, tag string) {
	if at := strings.IndexByte(image, '@'); at >= 0 {
		return image, "latest"
	}
	if colon := strings.LastIndexByte(image, ':'); colon >= 0 && !strings.Contains(image[colon:], "/") {
		return image[:colon], image[colon+1:]
	}
	return image, "latest"
}
