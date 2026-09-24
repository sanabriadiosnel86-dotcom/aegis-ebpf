package decoy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sanabriadiosnel86-dotcom/aegis-ebpf/internal/k8s"
)

// podAPI is the Kubernetes write surface the decoy needs. *k8s.Client
// satisfies it; tests supply a fake.
type podAPI interface {
	CreatePod(ctx context.Context, namespace string, manifest []byte) (k8s.CreatedPod, error)
	DeletePod(ctx context.Context, namespace, name string) error
}

// k8sDeployer deploys decoys as ephemeral pods in the offending pod's
// namespace, through the Kubernetes API.
type k8sDeployer struct {
	api   podAPI
	image string
}

// NewK8sDeployer returns a Deployer that creates decoy pods with the given
// image through api.
func NewK8sDeployer(api podAPI, image string) Deployer {
	if image == "" {
		image = DefaultImage
	}
	return &k8sDeployer{api: api, image: image}
}

func (d *k8sDeployer) Deploy(ctx context.Context, t Trigger) (Decoy, error) {
	if t.Namespace == "" {
		// Without the offending pod's namespace there is nowhere in-cluster
		// to place the decoy; this happens for host processes or before the
		// pod cache has resolved the container.
		return Decoy{}, fmt.Errorf("decoy: the offending workload has no known namespace")
	}
	manifest, err := json.Marshal(decoyPod(d.image, t))
	if err != nil {
		return Decoy{}, err
	}
	created, err := d.api.CreatePod(ctx, t.Namespace, manifest)
	if err != nil {
		return Decoy{}, err
	}
	return Decoy{ID: created.UID, Name: created.Name, Namespace: created.Namespace}, nil
}

func (d *k8sDeployer) Remove(ctx context.Context, dec Decoy) error {
	if dec.Namespace == "" || dec.Name == "" {
		return nil
	}
	return d.api.DeletePod(ctx, dec.Namespace, dec.Name)
}

// pod is the minimal pod manifest the decoy submits.
type pod struct {
	APIVersion string      `json:"apiVersion"`
	Kind       string      `json:"kind"`
	Metadata   podMetadata `json:"metadata"`
	Spec       podSpec     `json:"spec"`
}

type podMetadata struct {
	GenerateName string            `json:"generateName"`
	Namespace    string            `json:"namespace"`
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

type podSpec struct {
	RestartPolicy                 string      `json:"restartPolicy"`
	ActiveDeadlineSeconds         int64       `json:"activeDeadlineSeconds"`
	AutomountServiceAccountToken  bool        `json:"automountServiceAccountToken"`
	EnableServiceLinks            *bool       `json:"enableServiceLinks,omitempty"`
	TerminationGracePeriodSeconds int64       `json:"terminationGracePeriodSeconds"`
	Containers                    []container `json:"containers"`
}

type container struct {
	Name            string           `json:"name"`
	Image           string           `json:"image"`
	Command         []string         `json:"command"`
	Ports           []port           `json:"ports"`
	Resources       resources        `json:"resources"`
	SecurityContext *securityContext `json:"securityContext"`
}

type port struct {
	ContainerPort int32 `json:"containerPort"`
}

type resources struct {
	Requests map[string]string `json:"requests"`
	Limits   map[string]string `json:"limits"`
}

type securityContext struct {
	AllowPrivilegeEscalation bool           `json:"allowPrivilegeEscalation"`
	RunAsNonRoot             bool           `json:"runAsNonRoot"`
	RunAsUser                int64          `json:"runAsUser"`
	ReadOnlyRootFilesystem   bool           `json:"readOnlyRootFilesystem"`
	Capabilities             capabilities   `json:"capabilities"`
	SeccompProfile           seccompProfile `json:"seccompProfile"`
}

type capabilities struct {
	Drop []string `json:"drop"`
}

type seccompProfile struct {
	Type string `json:"type"`
}

// decoyPod builds the manifest of an inert decoy pod. Its container runs the
// same honeypot listener as the Docker decoy, under a hardened, non-root,
// read-only, capability-free security context.
func decoyPod(image string, t Trigger) pod {
	enableServiceLinks := false
	return pod{
		APIVersion: "v1",
		Kind:       "Pod",
		Metadata: podMetadata{
			GenerateName: "aegis-decoy-",
			Namespace:    t.Namespace,
			Labels: map[string]string{
				Label:                       "true",
				"app.kubernetes.io/name":    "aegis-ebpf-decoy",
				"app.kubernetes.io/part-of": "aegis-ebpf",
			},
			Annotations: annotations(t),
		},
		Spec: podSpec{
			RestartPolicy:                 "Never",
			ActiveDeadlineSeconds:         3600, // the decoy self-terminates after an hour
			AutomountServiceAccountToken:  false,
			EnableServiceLinks:            &enableServiceLinks,
			TerminationGracePeriodSeconds: 2,
			Containers: []container{{
				Name:    "decoy",
				Image:   image,
				Command: []string{"sh", "-c", listenerScript},
				Ports:   []port{{ContainerPort: decoyPort}},
				Resources: resources{
					Requests: map[string]string{"cpu": "10m", "memory": "16Mi"},
					Limits:   map[string]string{"memory": "64Mi"},
				},
				SecurityContext: &securityContext{
					AllowPrivilegeEscalation: false,
					RunAsNonRoot:             true,
					RunAsUser:                65532,
					ReadOnlyRootFilesystem:   true,
					Capabilities:             capabilities{Drop: []string{"ALL"}},
					SeccompProfile:           seccompProfile{Type: "RuntimeDefault"},
				},
			}},
		},
	}
}

func annotations(t Trigger) map[string]string {
	a := map[string]string{}
	if t.PodName != "" {
		a["aegis.offending-pod"] = t.PodName
	}
	if t.ContainerID != "" {
		a["aegis.offending-container"] = t.ContainerID
	}
	if len(a) == 0 {
		return nil
	}
	return a
}
