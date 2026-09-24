//! Identification of the container a process runs in, from its cgroup.

use serde::Serialize;

/// A container, as in the `Container` schema of api/openapi.yaml.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Container {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pod: Option<Pod>,
}

/// The Kubernetes pod of a container. Only its UID can be read from the
/// cgroup; the agent may resolve the rest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Pod {
    pub uid: String,
}

/// Prefixes that container runtimes give to the systemd scope of a
/// container, as in `cri-containerd-<id>.scope`.
const SCOPE_PREFIXES: [(&str, &str); 4] = [
    ("docker-", "docker"),
    ("cri-containerd-", "containerd"),
    ("crio-", "cri-o"),
    ("libpod-", "podman"),
];

/// Parses the content of `/proc/<pid>/cgroup`, in the cgroup v1 or v2 format.
pub fn from_proc_cgroup(content: &str) -> Option<Container> {
    content.lines().find_map(|line| {
        // hierarchy-ID:controller-list:cgroup-path
        let path = line.splitn(3, ':').nth(2)?;
        from_cgroup_path(path)
    })
}

/// Recognizes the cgroups that Docker, containerd, CRI-O and Podman create,
/// with the cgroupfs and systemd drivers, inside Kubernetes or not:
///
/// ```text
/// /docker/<id>
/// /system.slice/docker-<id>.scope
/// /kubepods/burstable/pod<uid>/<id>
/// /kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod<uid>.slice/cri-containerd-<id>.scope
/// ```
///
/// The innermost segment that holds a container ID wins, so that processes
/// in a sub-cgroup of their container are attributed to it.
pub fn from_cgroup_path(path: &str) -> Option<Container> {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let (i, id, runtime) = segments
        .iter()
        .enumerate()
        .rev()
        .find_map(|(i, s)| container_id(s).map(|(id, runtime)| (i, id, runtime)))?;
    let runtime = runtime.or_else(|| (i > 0 && segments[i - 1] == "docker").then_some("docker"));
    let pod = segments[..i]
        .iter()
        .rev()
        .find_map(|s| pod_uid(s))
        .map(|uid| Pod { uid });
    Some(Container {
        id: id.to_owned(),
        runtime,
        pod,
    })
}

fn container_id(segment: &str) -> Option<(&str, Option<&'static str>)> {
    let segment = segment.strip_suffix(".scope").unwrap_or(segment);
    for (prefix, runtime) in SCOPE_PREFIXES {
        if let Some(id) = segment.strip_prefix(prefix) {
            return is_container_id(id).then_some((id, Some(runtime)));
        }
    }
    is_container_id(segment).then_some((segment, None))
}

fn is_container_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Extracts the pod UID of a Kubernetes cgroup segment, such as
/// `pod<uid>` (cgroupfs) or `kubepods-burstable-pod<uid>.slice` (systemd,
/// where the dashes of the UID become underscores).
fn pod_uid(segment: &str) -> Option<String> {
    let segment = segment.strip_suffix(".slice").unwrap_or(segment);
    let uid = segment[segment.rfind("pod")? + 3..].replace('_', "-");
    is_uuid(&uid).then_some(uid)
}

fn is_uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "2d1f6c4a9e8b7d0c3f5a6b1e4d7c0a9f8e2b5d6c1a4f7e0b3d9c2a5f8e1b4d7c";
    const POD: &str = "6c3b1f0e-5d4a-4f2b-9e8d-7c6b5a4f3e2d";

    fn container(runtime: Option<&'static str>, pod: bool) -> Option<Container> {
        Some(Container {
            id: ID.to_owned(),
            runtime,
            pod: pod.then(|| Pod {
                uid: POD.to_owned(),
            }),
        })
    }

    #[test]
    fn recognizes_runtime_layouts() {
        let pod_systemd = POD.replace('-', "_");
        let cases = [
            (format!("/docker/{ID}"), container(Some("docker"), false)),
            (
                format!("/system.slice/docker-{ID}.scope"),
                container(Some("docker"), false),
            ),
            (
                format!("/machine.slice/libpod-{ID}.scope/container"),
                container(Some("podman"), false),
            ),
            (
                format!("/kubepods/burstable/pod{POD}/{ID}"),
                container(None, true),
            ),
            (
                format!(
                    "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod{pod_systemd}.slice/cri-containerd-{ID}.scope"
                ),
                container(Some("containerd"), true),
            ),
            (
                format!("/kubepods.slice/kubepods-pod{pod_systemd}.slice/crio-{ID}.scope"),
                container(Some("cri-o"), true),
            ),
            // conmon, the monitor of CRI-O, is not the container.
            (format!("/kubepods.slice/crio-conmon-{ID}.scope"), None),
            (
                "/user.slice/user-1000.slice/session-2.scope".to_owned(),
                None,
            ),
            ("/".to_owned(), None),
        ];
        for (path, want) in cases {
            assert_eq!(from_cgroup_path(&path), want, "{path}");
        }
    }

    #[test]
    fn parses_proc_cgroup() {
        let v1 = format!("12:pids:/docker/{ID}\n11:memory:/docker/{ID}\n0::/\n");
        assert_eq!(from_proc_cgroup(&v1), container(Some("docker"), false));
        let v2 = format!("0::/system.slice/docker-{ID}.scope\n");
        assert_eq!(from_proc_cgroup(&v2), container(Some("docker"), false));
        assert_eq!(from_proc_cgroup("0::/init.scope\n"), None);
    }
}
