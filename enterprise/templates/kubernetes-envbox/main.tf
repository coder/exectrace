// This template file is similar to the upstream Coder Kubernetes template.
//
// Changes:
// - Adds the exectrace sidecar container.
// - Updates the workspace container command to send the process ID namespace
//   inum to the sidecar container.
// - Updates the workspace agent subsystem to "exectrace" for telemetry.

terraform {
  required_providers {
    coder = {
      source  = "coder/coder"
      version = "0.6.12"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.12.1"
    }
  }
}

data "coder_parameter" "home_disk" {
  name        = "Disk Size"
  description = "How large should the disk storing the home directory be?"
  icon        = "https://cdn-icons-png.flaticon.com/512/2344/2344147.png"
  type        = "number"
  default     = 10
  mutable     = true
  validation {
    min = 10
    max = 100
  }
}

variable "use_kubeconfig" {
  type        = bool
  sensitive   = true
  default     = true
  description = <<-EOF
  Use host kubeconfig? (true/false)
  Set this to false if the Coder host is itself running as a Pod on the same
  Kubernetes cluster as you are deploying workspaces to.
  Set this to true if the Coder host is running outside the Kubernetes cluster
  for workspaces.  A valid "~/.kube/config" must be present on the Coder host.
  EOF
}

provider "coder" {
  feature_use_managed_variables = true
}

variable "namespace" {
  type        = string
  sensitive   = true
  description = "The namespace to create workspaces in (must exist prior to creating workspaces)"
}

variable "create_tun" {
  type        = bool
  sensitive   = true
  description = "Add a TUN device to the workspace."
  default     = false
}

variable "create_fuse" {
  type        = bool
  description = "Add a FUSE device to the workspace."
  sensitive   = true
  default     = false
}

variable "max_cpus" {
  type        = string
  sensitive   = true
  description = "Max number of CPUs the workspace may use (e.g. 2)."
}

variable "min_cpus" {
  type        = string
  sensitive   = true
  description = "Minimum number of CPUs the workspace may use (e.g. .1)."
}

variable "max_memory" {
  type        = string
  description = "Maximum amount of memory to allocate the workspace (in GB)."
  sensitive   = true
}

variable "min_memory" {
  type        = string
  description = "Minimum amount of memory to allocate the workspace (in GB)."
  sensitive   = true
}

provider "kubernetes" {
  # Authenticate via ~/.kube/config or a Coder-specific ServiceAccount, depending on admin preferences
  config_path = var.use_kubeconfig == true ? "~/.kube/config" : null
}

data "coder_workspace" "me" {}

resource "coder_agent" "main" {
  os             = "linux"
  arch           = "amd64"
  startup_script = <<EOT
    #!/bin/bash
    # home folder can be empty, so copying default bash settings
    if [ ! -f ~/.profile ]; then
      cp /etc/skel/.profile $HOME
    fi
    if [ ! -f ~/.bashrc ]; then
      cp /etc/skel/.bashrc $HOME
    fi
    # install and start code-server
    curl -fsSL https://code-server.dev/install.sh | sh -s -- --version 4.8.3 | tee code-server-install.log
    code-server --auth none --port 13337 | tee code-server-install.log &
  EOT
}

# code-server
resource "coder_app" "code-server" {
  agent_id     = coder_agent.main.id
  slug         = "code-server"
  display_name = "code-server"
  icon         = "/icon/code.svg"
  url          = "http://localhost:13337?folder=/home/coder"
  subdomain    = false
  share        = "owner"

  healthcheck {
    url       = "http://localhost:13337/healthz"
    interval  = 3
    threshold = 10
  }
}

resource "kubernetes_persistent_volume_claim" "home" {
  metadata {
    name      = "coder-${lower(data.coder_workspace.me.owner)}-${lower(data.coder_workspace.me.name)}-home"
    namespace = var.namespace
  }
  wait_until_bound = false
  spec {
    access_modes = ["ReadWriteOnce"]
    resources {
      requests = {
        storage = "${data.coder_parameter.home_disk.value}Gi"
      }
    }
  }
}

// NOTE: this section is added compared to the upstream kubernetes template
locals {
  exectrace_init_script = <<EOT
    set -eu
    pidns_inum=$(readlink /proc/self/ns/pid | sed 's/[^0-9]//g')
    if [ -z "$pidns_inum" ]; then
      echo "Could not determine process ID namespace inum"
      exit 1
    fi

    # Before we start the script, does curl exist?
    if ! command -v curl >/dev/null 2>&1; then
      echo "curl is required to download the Coder binary"
      echo "Please install curl to your image and try again"
      # 127 is command not found.
      exit 127
    fi

    echo "Sending process ID namespace inum to exectrace sidecar"
    rc=0
    max_retry=5
    counter=0
    until [ $counter -ge $max_retry ]; do
      set +e
      curl \
        --fail \
        --silent \
        --connect-timeout 5 \
        -X POST \
        -H "Content-Type: text/plain" \
        --data "$pidns_inum" \
        http://127.0.0.1:56123
      rc=$?
      set -e
      if [ $rc -eq 0 ]; then
        break
      fi

      counter=$((counter+1))
      echo "Curl failed with exit code $${rc}, attempt $${counter}/$${max_retry}; Retrying in 3 seconds..."
      sleep 3
    done
    if [ $rc -ne 0 ]; then
      echo "Failed to send process ID namespace inum to exectrace sidecar"
      exit $rc
    fi

  EOT
}

resource "kubernetes_pod" "main" {
  count = data.coder_workspace.me.start_count

  metadata {
    name      = "coder-${lower(data.coder_workspace.me.owner)}-${lower(data.coder_workspace.me.name)}"
    namespace = var.namespace
  }

  spec {
    restart_policy = "Never"

    // NOTE: this container is added compared to the upstream kubernetes
    // template
    container {
      name              = "exectrace"
      image             = "ghcr.io/coder/exectrace:latest"
      image_pull_policy = "Always"
      command = [
        "/opt/exectrace",
        "--init-address", "127.0.0.1:56123",
        "--label", "workspace_id=${data.coder_workspace.me.id}",
        "--label", "workspace_name=${data.coder_workspace.me.name}",
        "--label", "user_id=${data.coder_workspace.me.owner_id}",
        "--label", "username=${data.coder_workspace.me.owner}",
        "--label", "user_email=${data.coder_workspace.me.owner_email}",
      ]
      security_context {
        // exectrace must be started as root so it can attach probes into the
        // kernel to record process events with high throughput.
        run_as_user  = "0"
        run_as_group = "0"
        // exectrace requires a privileged container so it can control mounts
        // and perform privileged syscalls against the host kernel to attach
        // probes.
        privileged = true
      }
    }

    container {
      name              = "dev"
      image             = "ghcr.io/coder/envbox:latest"
      image_pull_policy = "Always"
      // NOTE: this command is changed compared to the upstream kubernetes
      // template
      command = [
        "sh",
        "-c",
        "${local.exectrace_init_script}\n\nexec /envbox docker",
      ]

      security_context {
        privileged = true
      }

      resources {
        requests = {
          "cpu" : "${var.min_cpus}"
          "memory" : "${var.min_memory}G"
        }

        limits = {
          "cpu" : "${var.max_cpus}"
          "memory" : "${var.max_memory}G"
        }
      }

      env {
        name  = "CODER_AGENT_TOKEN"
        value = coder_agent.main.token
      }

      env {
        name  = "CODER_AGENT_URL"
        value = data.coder_workspace.me.access_url
      }
      env {
        name = "CODER_AGENT_SUBSYSTEM"
        # The value "envbox" gets added by envbox.
        value = "exectrace"
      }

      env {
        name  = "CODER_INNER_IMAGE"
        value = "index.docker.io/codercom/enterprise-base@sha256:069e84783d134841cbb5007a16d9025b6aed67bc5b95eecc118eb96dccd6de68"
      }

      env {
        name  = "CODER_INNER_USERNAME"
        value = "coder"
      }

      env {
        name  = "CODER_BOOTSTRAP_SCRIPT"
        value = coder_agent.main.init_script
      }

      env {
        name  = "CODER_MOUNTS"
        value = "/home/coder:/home/coder"
      }

      env {
        name  = "CODER_ADD_FUSE"
        value = var.create_fuse
      }

      env {
        name  = "CODER_INNER_HOSTNAME"
        value = data.coder_workspace.me.name
      }

      env {
        name  = "CODER_ADD_TUN"
        value = var.create_tun
      }

      env {
        name = "CODER_CPUS"
        value_from {
          resource_field_ref {
            resource = "limits.cpu"
          }
        }
      }

      env {
        name = "CODER_MEMORY"
        value_from {
          resource_field_ref {
            resource = "limits.memory"
          }
        }
      }

      volume_mount {
        mount_path = "/home/coder"
        name       = "home"
        read_only  = false
        sub_path   = "home"
      }

      volume_mount {
        mount_path = "/var/lib/coder/docker"
        name       = "home"
        sub_path   = "cache/docker"
      }

      volume_mount {
        mount_path = "/var/lib/coder/containers"
        name       = "home"
        sub_path   = "cache/containers"
      }

      volume_mount {
        mount_path = "/var/lib/sysbox"
        name       = "sysbox"
      }

      volume_mount {
        mount_path = "/var/lib/containers"
        name       = "home"
        sub_path   = "envbox/containers"
      }

      volume_mount {
        mount_path = "/var/lib/docker"
        name       = "home"
        sub_path   = "envbox/docker"
      }

      volume_mount {
        mount_path = "/usr/src"
        name       = "usr-src"
      }

      volume_mount {
        mount_path = "/lib/modules"
        name       = "lib-modules"
      }
    }

    volume {
      name = "home"
      persistent_volume_claim {
        claim_name = kubernetes_persistent_volume_claim.home.metadata.0.name
        read_only  = false
      }
    }

    volume {
      name = "sysbox"
      empty_dir {}
    }

    volume {
      name = "usr-src"
      host_path {
        path = "/usr/src"
        type = ""
      }
    }

    volume {
      name = "lib-modules"
      host_path {
        path = "/lib/modules"
        type = ""
      }
    }
  }
}
