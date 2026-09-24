package decoy

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/sanabriadiosnel86-dotcom/aegis-ebpf/internal/events"
	"github.com/sanabriadiosnel86-dotcom/aegis-ebpf/internal/k8s"
)

// fakePodAPI records the manifests it is asked to create.
type fakePodAPI struct {
	created   []string // namespaces
	manifests [][]byte
	deleted   [][2]string // {namespace, name}
	err       error
}

func (f *fakePodAPI) CreatePod(_ context.Context, namespace string, manifest []byte) (k8s.CreatedPod, error) {
	if f.err != nil {
		return k8s.CreatedPod{}, f.err
	}
	f.created = append(f.created, namespace)
	f.manifests = append(f.manifests, manifest)
	return k8s.CreatedPod{Name: "aegis-decoy-abcde", Namespace: namespace, UID: "uid-1"}, nil
}

func (f *fakePodAPI) DeletePod(_ context.Context, namespace, name string) error {
	f.deleted = append(f.deleted, [2]string{namespace, name})
	return nil
}

func TestK8sDeployerCreatesHardenedPod(t *testing.T) {
	api := &fakePodAPI{}
	dep := NewK8sDeployer(api, "alpine:3.20")
	decoy, err := dep.Deploy(context.Background(), Trigger{
		ContainerID: webID,
		Namespace:   "shop",
		PodName:     "web-7d9f",
		Severity:    "critical",
	})
	if err != nil {
		t.Fatal(err)
	}
	if decoy.Namespace != "shop" || decoy.Name != "aegis-decoy-abcde" || decoy.ID != "uid-1" {
		t.Fatalf("decoy = %+v, want the created pod in shop", decoy)
	}
	if len(api.created) != 1 || api.created[0] != "shop" {
		t.Fatalf("created in namespaces %v, want [shop]", api.created)
	}

	// The manifest must describe an inert, hardened, non-root pod.
	var p pod
	if err := json.Unmarshal(api.manifests[0], &p); err != nil {
		t.Fatal(err)
	}
	if p.Kind != "Pod" || p.Metadata.Namespace != "shop" {
		t.Errorf("manifest kind/namespace = %s/%s", p.Kind, p.Metadata.Namespace)
	}
	if p.Metadata.Labels[Label] != "true" {
		t.Errorf("decoy pod is not labelled %s=true: %v", Label, p.Metadata.Labels)
	}
	if p.Metadata.Annotations["aegis.offending-pod"] != "web-7d9f" {
		t.Errorf("missing offending-pod annotation: %v", p.Metadata.Annotations)
	}
	if p.Spec.RestartPolicy != "Never" || p.Spec.ActiveDeadlineSeconds == 0 || p.Spec.AutomountServiceAccountToken {
		t.Errorf("pod spec is not ephemeral/tokenless: %+v", p.Spec)
	}
	if len(p.Spec.Containers) != 1 {
		t.Fatalf("want exactly one container, got %d", len(p.Spec.Containers))
	}
	c := p.Spec.Containers[0]
	if c.Image != "alpine:3.20" || len(c.Ports) != 1 || c.Ports[0].ContainerPort != decoyPort {
		t.Errorf("container image/port = %s/%v", c.Image, c.Ports)
	}
	sc := c.SecurityContext
	if sc == nil || sc.AllowPrivilegeEscalation || !sc.RunAsNonRoot || !sc.ReadOnlyRootFilesystem ||
		len(sc.Capabilities.Drop) != 1 || sc.Capabilities.Drop[0] != "ALL" {
		t.Errorf("security context is not hardened: %+v", sc)
	}
}

func TestK8sDeployerNeedsNamespace(t *testing.T) {
	api := &fakePodAPI{}
	dep := NewK8sDeployer(api, "")
	// A host process has no pod namespace: nothing is created.
	if _, err := dep.Deploy(context.Background(), Trigger{ContainerID: webID}); err == nil {
		t.Error("Deploy succeeded without a namespace")
	}
	if len(api.created) != 0 {
		t.Errorf("a pod was created without a namespace: %v", api.created)
	}
}

func TestK8sDeployerRemove(t *testing.T) {
	api := &fakePodAPI{}
	dep := NewK8sDeployer(api, "")
	if err := dep.Remove(context.Background(), Decoy{Name: "aegis-decoy-abcde", Namespace: "shop"}); err != nil {
		t.Fatal(err)
	}
	if len(api.deleted) != 1 || api.deleted[0] != [2]string{"shop", "aegis-decoy-abcde"} {
		t.Errorf("deleted %v, want the decoy in shop", api.deleted)
	}
	// A decoy without an identity is a no-op, not an error.
	if err := dep.Remove(context.Background(), Decoy{}); err != nil {
		t.Errorf("removing an empty decoy: %v", err)
	}
}

func TestResponderPlacesDecoyInPodNamespace(t *testing.T) {
	api := &fakePodAPI{}
	r := NewWithDeployer(Config{MinInterval: 1}, NewK8sDeployer(api, ""))
	ev := critical(webID)
	ev.Container.Pod = &events.Pod{Name: "web-7d9f", Namespace: "shop"}
	r.Respond(ev)
	if len(api.created) != 1 || api.created[0] != "shop" {
		t.Errorf("responder created decoys in %v, want [shop]", api.created)
	}
	if d := r.Deployed(); len(d) != 1 || d[0].Namespace != "shop" {
		t.Errorf("tracked decoys = %+v, want one in shop", d)
	}
}
