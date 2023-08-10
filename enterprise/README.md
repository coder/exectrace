# Exectrace for Coder v2

A wrapper around Coder's open source
[exectrace](https://github.com/coder/exectrace) library for providing workspace
process logging in Kubernetes on Linux for
[Coder v2](https://github.com/coder/coder).

> Note: The enterprise directory of this repo, including the exectrace binary
> and image, are enterprise-licensed. Workspace process logging is an enterprise
> feature in Coder v2.

> If you are looking for documentation on how to use workspace process logging
> in Coder v1, please refer to the
> [documentation](https://coder.com/docs/coder/latest/admin/workspace-management/process-logging)
> and reach out to us if you need any assistance.

This works by creating a sidecar inside the same Linux process namespace and
logging all processes created inside the namespace, even processes in nested
namespaces (i.e. from Docker containers).

## Usage in Kubernetes

Use the Kubernetes template in the [templates/kubernetes](templates/kubernetes)
directory as your starting point. This template is similar to the
[kubernetes](./templates/kubernetes) template shipped with Coder.

The main changes are:

- Adds some shell code before starting the Coder agent to submit the process ID
  namespace inum to the sibling container, which ensures that workspace startup
  waits for the exectrace container to be running.
- Adds the exectrace container to the pod.

## Usage in Kubernetes with Envbox

Same as above, but use the [kubernetes-envbox](./templates/kubernetes-envbox)
template instead.

## Usage outside of Kubernetes

This binary/image only supports Kubernetes, although technically it can be made
to work outside of Kubernetes by ensuring the workspace and the sidecar are
inside the same process ID namespace. Support for usage outside of Kubernetes is
not offered, but please reach out to us if you need this outside of Kubernetes
and we will see what we can do.

## License

Coder Enterprise license. See [LICENSE.enterprise](../LICENSE.enterprise).
