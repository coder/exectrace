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
      version = "~> 0.7.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.18"
    }
  }
}

provider "coder" {
  feature_use_managed_variables = true
}

variable "use_kubeconfig" {
  type        = bool
  description = <<-EOF
  Use host kubeconfig? (true/false)

  Set this to false if the Coder host is itself running as a Pod on the same
  Kubernetes cluster as you are deploying workspaces to.

  Set this to true if the Coder host is running outside the Kubernetes cluster
  for workspaces.  A valid "~/.kube/config" must be present on the Coder host.
  EOF
  default     = false
}

variable "namespace" {
  type        = string
  description = "The Kubernetes namespace to create workspaces in (must exist prior to creating workspaces)"
}

data "coder_parameter" "cpu" {
  name         = "cpu"
  display_name = "CPU"
  description  = "The number of CPU cores"
  default      = "2"
  icon         = "/icon/memory.svg"
  mutable      = true
  option {
    name  = "2 Cores"
    value = "2"
  }
  option {
    name  = "4 Cores"
    value = "4"
  }
  option {
    name  = "6 Cores"
    value = "6"
  }
  option {
    name  = "8 Cores"
    value = "8"
  }
}

data "coder_parameter" "memory" {
  name         = "memory"
  display_name = "Memory"
  description  = "The amount of memory in GB"
  default      = "2"
  icon         = "/icon/memory.svg"
  mutable      = true
  option {
    name  = "2 GB"
    value = "2"
  }
  option {
    name  = "4 GB"
    value = "4"
  }
  option {
    name  = "6 GB"
    value = "6"
  }
  option {
    name  = "8 GB"
    value = "8"
  }
}

data "coder_parameter" "home_disk_size" {
  name         = "home_disk_size"
  display_name = "Home disk size"
  description  = "The size of the home disk in GB"
  default      = "10"
  type         = "number"
  icon         = "/emojis/1f4be.png"
  mutable      = false
  validation {
    min = 1
    max = 99999
  }
}

provider "kubernetes" {
  # Authenticate via ~/.kube/config or a Coder-specific ServiceAccount, depending on admin preferences
  config_path = var.use_kubeconfig == true ? "~/.kube/config" : null
}

data "coder_workspace" "me" {}

resource "coder_agent" "main" {
  os                     = "linux"
  arch                   = "amd64"
  startup_script_timeout = 180
  startup_script         = <<-EOT
    set -e

    # install and start code-server
    curl -fsSL https://code-server.dev/install.sh | sh -s -- --method=standalone --prefix=/tmp/code-server --version 4.11.0
    /tmp/code-server/bin/code-server --auth none --port 13337 >/tmp/code-server.log 2>&1 &
  EOT

  # The following metadata blocks are optional. They are used to display
  # information about your workspace in the dashboard. You can remove them
  # if you don't want to display any information.
  # For basic resources, you can use the `coder stat` command.
  # If you need more control, you can write your own script.
  metadata {
    display_name = "CPU Usage"
    key          = "0_cpu_usage"
    script       = "coder stat cpu"
    interval     = 10
    timeout      = 1
  }

  metadata {
    display_name = "RAM Usage"
    key          = "1_ram_usage"
    script       = "coder stat mem"
    interval     = 10
    timeout      = 1
  }

  metadata {
    display_name = "Home Disk"
    key          = "3_home_disk"
    script       = "coder stat disk --path $${HOME}"
    interval     = 60
    timeout      = 1
  }

  metadata {
    display_name = "CPU Usage (Host)"
    key          = "4_cpu_usage_host"
    script       = "coder stat cpu --host"
    interval     = 10
    timeout      = 1
  }

  metadata {
    display_name = "Memory Usage (Host)"
    key          = "5_mem_usage_host"
    script       = "coder stat mem --host"
    interval     = 10
    timeout      = 1
  }

  metadata {
    display_name = "Load Average (Host)"
    key          = "6_load_host"
    # get load avg scaled by number of cores
    script   = <<EOT
      echo "`cat /proc/loadavg | awk '{ print $1 }'` `nproc`" | awk '{ printf "%0.2f", $1/$2 }'
    EOT
    interval = 60
    timeout  = 1
  }
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
    labels = {
      "app.kubernetes.io/name"     = "coder-pvc"
      "app.kubernetes.io/instance" = "coder-pvc-${lower(data.coder_workspace.me.owner)}-${lower(data.coder_workspace.me.name)}"
      "app.kubernetes.io/part-of"  = "coder"
      // Coder specific labels.
      "com.coder.resource"       = "true"
      "com.coder.workspace.id"   = data.coder_workspace.me.id
      "com.coder.workspace.name" = data.coder_workspace.me.name
      "com.coder.user.id"        = data.coder_workspace.me.owner_id
      "com.coder.user.username"  = data.coder_workspace.me.owner
    }
    annotations = {
      "com.coder.user.email" = data.coder_workspace.me.owner_email
    }
  }
  wait_until_bound = false
  spec {
    access_modes = ["ReadWriteOnce"]
    resources {
      requests = {
        storage = "${data.coder_parameter.home_disk_size.value}Gi"
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
    labels = {
      "app.kubernetes.io/name"     = "coder-workspace"
      "app.kubernetes.io/instance" = "coder-workspace-${lower(data.coder_workspace.me.owner)}-${lower(data.coder_workspace.me.name)}"
      "app.kubernetes.io/part-of"  = "coder"
      // Coder specific labels.
      "com.coder.resource"       = "true"
      "com.coder.workspace.id"   = data.coder_workspace.me.id
      "com.coder.workspace.name" = data.coder_workspace.me.name
      "com.coder.user.id"        = data.coder_workspace.me.owner_id
      "com.coder.user.username"  = data.coder_workspace.me.owner
    }
    annotations = {
      "com.coder.user.email" = data.coder_workspace.me.owner_email
    }
  }
  spec {
    security_context {
      run_as_user = "1000"
      fs_group    = "1000"
    }

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
      image             = "codercom/enterprise-base:ubuntu"
      image_pull_policy = "Always"
      // NOTE: this command is changed compared to the upstream kubernetes
      // template
      command = [
        "sh",
        "-c",
        "${local.exectrace_init_script}\n\n${coder_agent.main.init_script}",
      ]
      security_context {
        run_as_user = "1000"
      }
      env {
        name  = "CODER_AGENT_TOKEN"
        value = coder_agent.main.token
      }
      env {
        name  = "CODER_AGENT_SUBSYSTEM"
        value = "exectrace"
      }
      resources {
        requests = {
          "cpu"    = "250m"
          "memory" = "512Mi"
        }
        limits = {
          "cpu"    = "${data.coder_parameter.cpu.value}"
          "memory" = "${data.coder_parameter.memory.value}Gi"
        }
      }
      volume_mount {
        mount_path = "/home/coder"
        name       = "home"
        read_only  = false
      }
    }

    volume {
      name = "home"
      persistent_volume_claim {
        claim_name = kubernetes_persistent_volume_claim.home.metadata.0.name
        read_only  = false
      }
    }


    affinity {
      pod_anti_affinity {
        // This affinity attempts to spread out all workspace pods evenly across
        // nodes.
        preferred_during_scheduling_ignored_during_execution {
          weight = 1
          pod_affinity_term {
            topology_key = "kubernetes.io/hostname"
            label_selector {
              match_expressions {
                key      = "app.kubernetes.io/name"
                operator = "In"
                values   = ["coder-workspace"]
              }
            }
          }
        }
      }
    }
  }
}
