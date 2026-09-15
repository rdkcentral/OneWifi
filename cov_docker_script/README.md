# 🔧 Coverity Native Build System for RDK-B Components

**Generic, reusable build system enabling Coverity static analysis for any RDK-B component.**

[![Docker](https://img.shields.io/badge/Docker-Enabled-blue)](https://github.com/rdkcentral/docker-rdk-ci)
[![GitHub Actions](https://img.shields.io/badge/CI-GitHub_Actions-green)](https://github.com/rdkcentral/moca-agent/blob/feature/cov_native_build/.github/workflows/native-build.yml)
[![Coverity](https://img.shields.io/badge/Coverity-Ready-orange)](https://www.synopsys.com/software-integrity/security-testing/static-analysis-sast.html)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
  - [Quick Start](#quick-start)
  - [Docker Environment Setup](#docker-environment-setup)
  - [Component Integration](#component-integration)
- [Configuration Guide](#configuration-guide)
  - [Scripts Overview](#scripts-overview)
  - [JSON Configuration](#json-configuration)
  - [Build Types](#build-types)
  - [Environment Variables](#environment-variables)
- [Advanced Usage](#advanced-usage)
  - [Advanced Features](#advanced-features)
  - [Troubleshooting](#troubleshooting)
- [CI/CD Integration](#cicd-integration)
  - [GitHub Actions](#github-actions-integration)
  - [Coverity Enablement](#coverity-enablement-flow)
- [Migration Guide](#migration-guide)
- [Governance & Rules](#governance--rules)
- [References](#references)

---

## 🎯 Overview

### What is This?

This build system provides a **standardized native build workflow** that enables Coverity static analysis for RDK-B components by:

- ✅ Building components **outside the Yocto environment**
- ✅ Explicitly declaring **all dependencies in JSON**
- ✅ Validating builds in **Docker containers**
- ✅ Automating validation through **GitHub Actions**

**The validated native build is a mandatory prerequisite for enabling Coverity scanning.**

### Purpose

| Goal | Description |
|------|-------------|
| 🛡️ **Enable Coverity** | Standardized pathway to static analysis |
| 🔄 **Build Reproducibility** | Consistent builds across environments |
| 📦 **Dependency Management** | JSON-driven dependency resolution |
| 🚀 **Component Onboarding** | Scalable integration process |

### System Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│     Docker      │────▶│ GitHub Actions   │────▶│    Coverity     │
│  (Build Env)    │     │  (Validation)    │     │   (Analysis)    │
└─────────────────┘     └──────────────────┘     └─────────────────┘
       │                         │                         │
       │                         │                         │
   Provides                  Validates                 Consumes
   consistent                 build                    validated
   environment                success                  configuration
```

#### Component Responsibilities

| Component | Responsibilities |
|-----------|------------------|
| **Docker** | • Consistent build environment<br>• Pre-installed toolchain<br>• System-level dependencies |
| **GitHub Actions** | • Automated build triggers<br>• PR validation<br>• Quality gate enforcement |
| **Coverity** | • Static analysis<br>• Security scanning<br>• Code quality metrics |

### High-Level Workflow

1. **Setup** → Docker environment prepared using [docker-rdk-ci](https://github.com/rdkcentral/docker-rdk-ci)
2. **Integrate** → Component adds `cov_docker_script` directory
3. **Configure** → Dependencies declared in JSON
4. **Build** → Native build executes locally and in CI
5. **Validate** → GitHub Actions confirms build stability
6. **Enable** → Component eligible for Coverity scanning
7. **Onboard** → CMFSUPPORT ticket raised

---

## 📦 Prerequisites

### Required Tools

| Tool | Purpose | Minimum Version |
|------|---------|-----------------|
| `bash` | Shell scripting | 4.0+ |
| `git` | Repository cloning | - |
| `jq` | JSON parsing | - |
| `gcc`/`g++` | C/C++ compiler | - |
| `make` | Build automation | - |
| `python3` | Patching & scripts | - |

### Optional Tools (Dependency-Based)

| Tool | When Required |
|------|---------------|
| `autoconf`, `automake`, `libtool` | Autotools builds |
| `cmake` | CMake builds |
| `meson`, `ninja` | Meson builds |
| `pkg-config` | Dependency detection |

### Docker Access

- Docker installed and running
- Access to [docker-rdk-ci](https://github.com/rdkcentral/docker-rdk-ci)
- Permissions to create/run containers

---

## 🚀 Getting Started

### Quick Start

**For existing components with `cov_docker_script` already integrated:**

```bash
# Navigate to component root
cd /path/to/your-component

# Run complete build pipeline
./cov_docker_script/common_external_build.sh

# Clean build (removes previous artifacts)
CLEAN_BUILD=true ./cov_docker_script/common_external_build.sh
```

**What happens:**
1. ⚙️ **Setup Dependencies** → Clones repos, copies headers, builds libraries
2. 🔨 **Build Component** → Applies patches, builds component, installs libraries

---

### Docker Environment Setup

#### Step 1: Clone docker-rdk-ci

```bash
git clone https://github.com/rdkcentral/docker-rdk-ci.git
cd docker-rdk-ci
```

#### Step 2: Update Dockerfile (If Needed)

⚠️ **Only required when system-level packages are missing**

**When to update:**
- Native build fails due to missing system packages
- Required RDK-B dependency not in standard image

**Process:**
1. Update Dockerfile locally
2. Validate build completes successfully
3. Raise PR to [docker-rdk-ci](https://github.com/rdkcentral/docker-rdk-ci)

```dockerfile
# Example: Adding missing packages
RUN apt-get update && apt-get install -y \
    libdbus-1-dev \
    libssl-dev \
    your-missing-package
```

> 💡 **Note:** Component-specific headers/libraries must be declared in `component_config.json`, **not** in Dockerfile.

#### Step 3: Build or Pull Docker Image

**Option A: Build Locally (After Dockerfile Updates)**

```bash
sudo docker build --network=host -t rdkb-native-build .

# Verify
sudo docker images
```

**Option B: Use Official Image (No Changes Needed)**

```bash
docker pull ghcr.io/rdkcentral/docker-rdk-ci:latest
```

#### Step 4: Create and Run Container

```bash
# Create volume mount directory
mkdir -p $HOME/docker_files

# Run container
sudo docker run \
  --name=rdkb-builder \
  --volume=$HOME/docker_files:/home/$USER \
  --restart=no \
  --runtime=runc \
  -t -d \
  rdkb-native-build

# Start if not running
sudo docker start rdkb-builder
```

#### Step 5: Configure User Permissions

**Prevent file permission issues between host and container:**

```bash
# Add group
sudo docker exec rdkb-builder groupadd $USER --gid=$(id -g $USER)

# Add user
sudo docker exec rdkb-builder useradd -m $USER -G users \
  --uid=$(id -u $USER) --gid=$(id -g $USER)
```

#### Step 6: Access Container

```bash
sudo docker exec --user $USER -it rdkb-builder /bin/bash
```

✅ **Container is now ready for native builds!**

---

### Component Integration

#### Step 1: Clone Your Component

```bash
git clone https://github.com/rdkcentral/your-component.git
cd your-component
```

#### Step 2: Add cov_docker_script Directory

**Copy the directory structure from reference:**

```bash
# Example structure
your-component/
├── cov_docker_script/
│   ├── common_build_utils.sh        # Utility functions
│   ├── setup_dependencies.sh        # Dependency setup
│   ├── build_native.sh              # Component build
│   ├── common_external_build.sh     # Orchestrator
│   ├── component_config.json        # Configuration
│   └── configure_options.conf       # Build flags (optional)
├── source/
└── ... (component files)
```

**Reference:** [moca-agent/cov_docker_script](https://github.com/rdkcentral/moca-agent/blob/feature/cov_native_build/cov_docker_script)

> ⚠️ **Important:** Scripts must remain unchanged. Only JSON/conf files are modifiable.

#### Step 3: Configure Dependencies

**Edit `component_config.json` to declare all dependencies:**

```json
{
  "dependencies": {
    "repos": [
      {
        "name": "your-dependency",
        "repo": "https://github.com/org/dependency.git",
        "branch": "main",
        "header_paths": [
          { "source": "include", "destination": "$HOME/usr/include/rdkb" }
        ],
        "build": {
          "type": "cmake",
          "cmake_flags": "-DCMAKE_INSTALL_PREFIX=$HOME/usr"
        }
      }
    ]
  },
  "native_component": {
    "name": "your-component",
    "include_path": "$HOME/usr/include/rdkb/",
    "lib_output_path": "$HOME/usr/local/lib/",
    "build": {
      "type": "autotools",
      "configure_options": [
        "CPPFLAGS=-I$HOME/usr/include/rdkb",
        "LDFLAGS=-L$HOME/usr/local/lib"
      ]
    }
  }
}
```

#### Step 4: Run Native Build

```bash
./cov_docker_script/common_external_build.sh
```

#### Step 5: Resolve Build Failures

**Build fails? Follow this process:**

1. 🔍 **Identify** → Missing headers or libraries
2. 📝 **Update** → JSON configuration
3. 🔄 **Re-run** → Build again

```bash
# Check build logs
ls -la $HOME/build/

# Verify headers copied
ls -la $HOME/usr/include/rdkb/

# Verify libraries built
ls -la $HOME/usr/local/lib/
```

> ❌ **No script modifications allowed!**

---

## 📖 Configuration Guide

### Scripts Overview

#### 1️⃣ common_build_utils.sh

**Shared utility library** with common functions for all build scripts.

| Function | Purpose |
|----------|---------|
| `log()`, `ok()`, `warn()`, `err()`, `step()` | Color-coded logging |
| `expand_path()` | Expands `$HOME` variables |
| `check_dependencies()` | Validates system tools |
| `clone_repo()` | Git repository cloning |
| `copy_headers()` | Header file copying |
| `copy_python_files_generic()` | Python file copying |
| `apply_patch()` | Patch application (replace/create) |
| `build_autotools()`, `build_cmake()`, `build_meson()` | Build functions |
| `execute_commands()` | Custom command execution |
| `copy_libraries()` | Library installation |
| `print_banner()`, `print_section()` | Formatting utilities |

**Usage:** Sourced by other scripts (not run directly)

```bash
source common_build_utils.sh
```

**Auto-configured:**
- Validates presence of git, jq, gcc, make
- Sets up color-coded terminal output
- Exports all functions for use in other scripts

---

#### 2️⃣ setup_dependencies.sh

**Dependency setup script** that clones, builds, and installs dependencies.

**Process:**
1. Reads `component_config.json`
2. Clones repos to `$HOME/build/`
3. Copies headers to `$HOME/usr/include/rdkb/`
4. Builds libraries (if configured)
5. Installs to `$HOME/usr/local/lib/`
6. Configures PKG_CONFIG_PATH and LD_LIBRARY_PATH

**Usage:**

```bash
# Default config
./setup_dependencies.sh

# Custom config
./setup_dependencies.sh /path/to/config.json

# Clean build
CLEAN_BUILD=true ./setup_dependencies.sh

# Custom directories
BUILD_DIR=/tmp/build USR_DIR=/opt/rdkb ./setup_dependencies.sh
```

**Environment Variables:**
- `BUILD_DIR` - Where to clone repos (default: `$HOME/build`)
- `USR_DIR` - Install directory (default: `$HOME/usr`)
- `CLEAN_BUILD` - Set to `true` to remove previous artifacts

**Outputs:**
- Headers: `$HOME/usr/include/rdkb/`
- Libraries: `$HOME/usr/local/lib/`, `$HOME/usr/lib/`

---

#### 3️⃣ build_native.sh

**Component build script** that builds the native component.

**Process:**
1. Processes component headers
2. Applies patches (replace or create)
3. Copies Python files (for code generation)
4. Runs pre-build commands
5. Configures build environment
6. Executes build (autotools/cmake)
7. Installs libraries

**Usage:**

```bash
# Default
./build_native.sh

# Custom paths
./build_native.sh /path/to/config.json /path/to/component

# With overrides
HEADER_PATH=/custom/include ./build_native.sh
```

**Prerequisites:**
- `setup_dependencies.sh` completed
- Headers/libraries in `$HOME/usr/`

**Output:**
- Component libraries in path specified by `native_component.lib_output_path`
- Default: `$HOME/usr/local/lib/`

---

#### 4️⃣ common_external_build.sh

**Orchestrator script** that runs the complete pipeline.

**Process:**
1. Validates configuration
2. Runs `setup_dependencies.sh` (Step 1/2)
3. Runs `build_native.sh` (Step 2/2)
4. Displays status

**Usage:**

```bash
# Complete build
./common_external_build.sh

# Custom paths
./common_external_build.sh /path/to/config.json /path/to/component

# Clean build
CLEAN_BUILD=true ./common_external_build.sh
```

✅ **This is the recommended entry point**

**Output:**
- Complete dependency setup
- Built component with all libraries
- Success/failure status for entire pipeline

---

#### 5️⃣ component_config.json

**JSON configuration** defining dependencies and build settings.

**Key Sections:**
- `dependencies.repos[]` → Dependency repositories
- `native_component` → Component build configuration
- `source_patches[]` → Patches to apply
- `pre_build_commands[]` → Commands before build

**Not a script, but required by all build scripts.**

See [JSON Configuration](#json-configuration) section for details.

---

#### 6️⃣ configure_options.conf

**Optional configuration file** for complex autotools builds.

**Format:**

```properties
# Section headers in square brackets
[CPPFLAGS]
-I$HOME/usr/include/rdkb/
-DFEATURE_FLAG

[CFLAGS]
-ffunction-sections
-fdata-sections

[LDFLAGS]
-L$HOME/usr/local/lib/
-Wl,--allow-shlib-undefined
```

**Benefits:**
- ✅ One flag per line with comments
- ✅ Section-based organization (preprocessor, compiler, linker)
- ✅ Better version control diffs
- ✅ Cleaner JSON configuration

**Sections:**
- `[CPPFLAGS]` - Preprocessor flags (includes with `-I`, defines with `-D`)
- `[CFLAGS]` - C compiler flags (optimization, warnings, debugging)
- `[LDFLAGS]` - Linker flags (library paths with `-L`, linker options with `-Wl`)

**Usage in JSON:**

```json
{
  "native_component": {
    "build": {
      "type": "autotools",
      "configure_options_file": "cov_docker_script/configure_options.conf"
    }
  }
}
```

> 💡 **Note:** Use `configure_options_file` **OR** `configure_options` array, not both.

---

### JSON Configuration

#### Dependencies Section

```json
{
  "dependencies": {
    "repos": [
      {
        "name": "repo-name",
        "repo": "https://github.com/org/repo.git",
        "branch": "main",
        "header_paths": [
          {
            "source": "include",
            "destination": "$HOME/usr/include/rdkb"
          }
        ],
        "source_patches": [
          {
            "file": "source/header.h",
            "type": "replace",
            "search": "old text",
            "replace": "new text"
          },
          {
            "file": "$HOME/usr/include/rdkb/header.h",
            "type": "replace",
            "search": "old text",
            "replace": "new text"
          }
        ],
        "build": {
          "type": "autotools|cmake|meson|commands|script",
          "configure_flags": "--prefix=$HOME/usr",
          "parallel_make": true
        }
      }
    ]
  }
}
```

**Field Reference:**

| Field | Required | Description |
|-------|----------|-------------|
| `name` | ✅ | Repository name |
| `repo` | ✅ | Git repository URL |
| `branch` | ✅ | Branch to clone |
| `header_paths[]` | ⬜ | Headers to copy |
| `source_patches[]` | ⬜ | Patches to apply to dependency |
| `build` | ⬜ | Build configuration (omit for header-only) |

---

#### Native Component Section

```json
{
  "native_component": {
    "name": "component-name",
    "include_path": "$HOME/usr/include/rdkb/",
    "lib_output_path": "$HOME/usr/local/lib/",
    "header_sources": [
      {
        "source": "source/include",
        "destination": "$HOME/usr/include/rdkb"
      }
    ],
    "source_patches": [
      {
        "file": "$HOME/usr/include/rdkb/header.h",
        "type": "replace",
        "search": "old text",
        "replace": "new text"
      },
      {
        "file": "$HOME/usr/include/rdkb/new.h",
        "type": "create",
        "content": "#ifndef NEW_H\n#define NEW_H\n#endif"
      }
    ],
    "pre_build_commands": [
      {
        "description": "Generate code from XML",
        "command": "python3 $HOME/usr/include/rdkb/generator.py input.xml output.c"
      }
    ],
    "build": {
      "type": "autotools",
      "configure_options_file": "cov_docker_script/configure_options.conf"
    }
  }
}
```

**Field Reference:**

| Field | Description |
|-------|-------------|
| `header_sources[]` | Component headers to copy (relative paths) |
| `source_patches[]` | Patches to apply (types: `replace`, `create`) |
| `pre_build_commands[]` | Commands before build (e.g., code generation) |
| `build` | Build configuration |

**Configuration Details:**
- `header_sources[]` - Component headers to copy before building. Source paths are relative to component directory.
- `source_patches[]` - Patches to apply after headers are copied. Supports two types:
  - `type: "replace"` - Replace text in existing file (requires `search` and `replace` fields)
  - `type: "create"` - Create new file with content (requires `content` field)
  - Use absolute paths with `$HOME` for files in install directories
- `pre_build_commands[]` - Commands to run after patches but before build (e.g., code generation). Each has `description` and `command`.
  - Automatically copies all Python files from `$PYTHON_SRC_DIR` to `$PYTHON_DST_DIR` before running commands
  - Useful for code generators, data transformers, or custom preprocessing
- `include_path` - Colon-separated include paths for building
- `lib_output_path` - Where to install built libraries

---

### Build Types

#### 🔨 Autotools

**Option 1: Inline Flags**

```json
{
  "build": {
    "type": "autotools",
    "configure_flags": "--prefix=$HOME/usr --enable-feature"
  }
}
```

**Option 2: Options Array**

```json
{
  "build": {
    "type": "autotools",
    "configure_options": [
      "CPPFLAGS=-I$HOME/usr/include/rdkb",
      "CFLAGS=-ffunction-sections",
      "LDFLAGS=-L$HOME/usr/local/lib"
    ]
  }
}
```

**Option 3: External File (Recommended for Complex Builds)**

```json
{
  "build": {
    "type": "autotools",
    "configure_options_file": "cov_docker_script/configure_options.conf"
  }
}
```

**Advanced Options:**

```json
{
  "build": {
    "type": "autotools",
    "configure_flags": "--prefix=$HOME/usr",
    "make_targets": ["all", "install"],
    "parallel_make": true
  }
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `make_targets` | `["all"]` | Make targets to build |
| `parallel_make` | `true` | Enable `-j$(nproc)` |

**When to use configure_options_file:**
- Complex builds with 20+ compiler flags
- Many preprocessor defines (-D flags)
- Multiple include/library paths
- Better maintainability and version control
- Cleaner JSON configuration

---

#### 🏗️ CMake

```json
{
  "build": {
    "type": "cmake",
    "build_dir": "build",
    "cmake_flags": "-DCMAKE_INSTALL_PREFIX=$HOME/usr -DBUILD_SHARED_LIBS=ON",
    "make_targets": ["all", "install"],
    "parallel_make": true
  }
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `build_dir` | `"build"` | CMake build directory |
| `cmake_flags` | - | CMake configuration flags |
| `make_targets` | `["all"]` | Make targets |
| `parallel_make` | `true` | Parallel compilation |

---

#### 🔩 Meson

```json
{
  "build": {
    "type": "meson",
    "build_dir": "builddir",
    "meson_flags": "--prefix=$HOME/usr --buildtype=release",
    "ninja_targets": ["all", "install"]
  }
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `build_dir` | `"builddir"` | Meson build directory |
| `meson_flags` | - | Meson setup flags |
| `ninja_targets` | `["all"]` | Ninja targets |

---

#### ⚡ Custom Commands

```json
{
  "build": {
    "type": "commands",
    "commands": [
      "meson setup build --prefix=$HOME/usr",
      "meson compile -C build",
      "meson install -C build"
    ]
  }
}
```

Execute custom build commands in sequence.

---

#### 📜 Custom Script

```json
{
  "build": {
    "type": "script",
    "script": "cov_docker_script/custom_build.sh"
  }
}
```

Execute a custom build script. Used for nested builds or complex build logic.

---

### Environment Variables

**Automatically configured by scripts:**

| Variable | Default | Description |
|----------|---------|-------------|
| `BUILD_DIR` | `$HOME/build` | Repository clone location |
| `USR_DIR` | `$HOME/usr` | Install directory |
| `PKG_CONFIG_PATH` | Auto-configured | Dependency detection |
| `LD_LIBRARY_PATH` | Auto-configured | Runtime linking |
| `CPPFLAGS` | Auto-configured | Include paths |
| `LDFLAGS` | Auto-configured | Library paths |
| `CLEAN_BUILD` | `false` | Set to `true` for clean build |

**Advanced variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `PYTHON_SRC_DIR` | `$HOME/build` | Python files source |
| `PYTHON_DST_DIR` | `$HOME/usr/include/rdkb` | Python files destination |
| `PARENT_BUILD_DIR` | - | Nested build coordination |
| `PARENT_USR_DIR` | - | Nested build coordination |

---

## 🚀 Advanced Usage

### Advanced Features

#### 🐍 Automatic Python File Copy

**Before `pre_build_commands`, Python files (`.py`) are auto-copied from dependencies.**

**How it works:**
1. Scans `$PYTHON_SRC_DIR` recursively for `.py` files
2. Copies to `$PYTHON_DST_DIR`
3. Makes utilities available for code generation

**Example:**

```json
{
  "pre_build_commands": [
    {
      "description": "Generate code from XML using dependency's Python script",
      "command": "python3 $HOME/usr/include/rdkb/dm_pack_code_gen.py config/data.xml output.c"
    }
  ]
}
```

**Customize directories:**

```bash
PYTHON_SRC_DIR=/custom/src PYTHON_DST_DIR=/custom/dst ./build_native.sh
```

---

#### 🔗 Nested Build Scripts

**When dependencies use nested scripts:**

```json
{
  "name": "common-library",
  "build": {
    "type": "script",
    "script": "cov_docker_script/common_external_build.sh"
  }
}
```

**Parent exports:**
- `PARENT_BUILD_DIR` → Parent's BUILD_DIR value
- `PARENT_USR_DIR` → Parent's USR_DIR value

This allows nested scripts to coordinate their build locations.

---

#### 🩹 Patch Types

**1. Replace Patch (Modify Existing Files)**

Replaces text in an existing file:

```json
{
  "file": "$HOME/usr/include/rdkb/header.h",
  "type": "replace",
  "search": "typedef struct _OLD",
  "replace": "typedef struct DBusLoop DBusLoop;\n\ntypedef struct _OLD"
}
```

**2. Create Patch (New Files)**

Creates a new file with specified content:

```json
{
  "file": "$HOME/usr/include/rdkb/generated.h",
  "type": "create",
  "content": "#ifndef GENERATED_H\n#define GENERATED_H\n\n// Auto-generated\n\n#endif"
}
```

---

#### 🎯 Build Target Customization

All build types support custom targets:

**Autotools/CMake:**

```json
{
  "build": {
    "type": "autotools",
    "make_targets": ["all", "install", "check"]
  }
}
```

**Meson:**

```json
{
  "build": {
    "type": "meson",
    "ninja_targets": ["all", "install", "test"]
  }
}
```

---

#### ⚙️ Parallel Build Control

Control parallel compilation (default: enabled):

```json
{
  "build": {
    "type": "cmake",
    "parallel_make": false
  }
}
```

**When to disable:**
- Build systems with race conditions
- Low-memory environments
- Debugging build issues

---

### Troubleshooting

#### ❌ Build fails with "command not found"

**For Docker Container Environments:**

If you're running builds in a Docker container and encounter missing tools, add the required packages to the Docker image:

1. Update the [docker-rdk-ci Dockerfile](https://github.com/rdkcentral/docker-rdk-ci/blob/main/Dockerfile)
2. Add missing packages to the appropriate `RUN apt-get install` section
3. Rebuild and use the updated Docker image

**For Native/Local Builds:**

Install required tools directly:

```bash
sudo apt-get install git jq gcc make autoconf automake libtool cmake python3
```

---

#### ❌ Dependencies fail to build

**Check:**
- `$HOME/build/<repo-name>/` for build logs
- `configure_flags` in JSON are correct
- System packages installed (cmake, meson, etc.)

---

#### ❌ Headers not found during component build

**Verify:**
- `setup_dependencies.sh` completed successfully
- `$HOME/usr/include/rdkb/` contains expected headers
- `header_paths` in JSON point to correct source directories

---

#### ❌ Libraries not found

**Check library directories:**
- `$HOME/usr/local/lib/` (primary location)
- `$HOME/usr/lib/` (secondary location)

**Verify:**
- Dependencies built successfully (look for `.so`, `.a` files)
- Build logs for `make install` errors

---

#### ❌ Patches fail to apply

**Common issues:**
- **File not found:** Verify file path is relative to component directory
- **Use `../`** for files outside component (e.g., `../usr/include/rdkb/header.h`)
- **Exact match required:** Search string must exactly match file content
- **Python3 required:** Ensure Python3 is installed

---

#### 🧹 Clean Build

Remove all previous build artifacts:

```bash
CLEAN_BUILD=true ./common_external_build.sh
```

---

#### ✅ Validate Configuration

```bash
# Check JSON syntax
jq . component_config.json

# List all dependencies
jq '.dependencies.repos[].name' component_config.json
```

---

#### 📂 Directory Structure After Build

```
$HOME/
├── build/                    # Cloned repositories
└── usr/
    ├── include/
    │   └── rdkb/            # All dependency headers
    ├── lib/                 # Secondary library location
    └── local/
        └── lib/             # Primary library location (.so, .a)
```

---

## 🔄 CI/CD Integration

### GitHub Actions Integration

The GitHub Actions workflow provides automated validation of the native build:

**Workflow Responsibilities:**
- ✅ Triggers the native build automatically on PR creation and updates
- ✅ Fails on compilation errors
- ✅ Exposes logs for troubleshooting
- ✅ Ensures consistent validation across components

**Successful CI validation is required before Coverity onboarding.**

**Example Workflow:**

```yaml
# .github/workflows/native-build.yml
name: Native Build

on:
  pull_request:
  push:
    branches: [main, develop]

jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/rdkcentral/docker-rdk-ci:latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Native Build
        run: ./cov_docker_script/common_external_build.sh
```

**The workflow validates that:**
1. All dependencies are correctly declared in JSON
2. The component builds successfully in a clean environment
3. No hardcoded paths or undeclared dependencies exist

**Reference Implementation:**
- [moca-agent native-build.yml](https://github.com/rdkcentral/moca-agent/blob/feature/cov_native_build/.github/workflows/native-build.yml)

---

### Coverity Enablement Flow

Once the native build is validated:

#### Step 1: Validate Build Stability

- ✅ Native build succeeds locally
- ✅ GitHub Actions workflow passes consistently
- ✅ All dependencies declared in JSON

#### Step 2: Raise CMFSUPPORT Ticket

**Include:**
- Component repository URL
- Reference validated native build configuration
- Link to successful GitHub Actions runs

#### Step 3: Coverity Integration

- Coverity scanning is enabled using the validated configuration
- Static analysis runs using the approved build flow
- Results are available in Coverity dashboard

**Key Principle:**
Native build validation enables Coverity integration.

---

## 📚 Migration Guide

### Adopting for Another Component

**These scripts are 100% generic and component-agnostic!**

#### Step 1: Copy the Scripts

```bash
# Copy all scripts to your component's build directory
cp -r /reference/cov_docker_script /path/to/new-component/

# Make executable
chmod +x /path/to/new-component/cov_docker_script/*.sh
```

#### Step 2: Create component_config.json

Create a new `component_config.json` for your component:

```json
{
  "_comment": "Component Build Configuration",
  "_version": "2.0",
  
  "dependencies": {
    "repos": [
      {
        "name": "your-dependency",
        "repo": "https://github.com/org/your-dependency.git",
        "branch": "main",
        "header_paths": [
          { "source": "include", "destination": "$HOME/usr/include/rdkb" }
        ],
        "build": {
          "type": "cmake",
          "cmake_flags": "-DCMAKE_INSTALL_PREFIX=$HOME/usr"
        }
      }
    ]
  },
  
  "native_component": {
    "name": "your-component-name",
    "include_path": "$HOME/usr/include/rdkb/",
    "lib_output_path": "$HOME/usr/local/lib/",
    "source_patches": [],
    "build": {
      "type": "autotools",
      "configure_options": [
        "CPPFLAGS=-I$HOME/usr/include/rdkb",
        "LDFLAGS=-L$HOME/usr/local/lib"
      ]
    }
  }
}
```

#### Step 3: Run the Build

```bash
cd /path/to/new-component/cov_docker_script
./common_external_build.sh
```

**That's it!** No script modifications needed. The scripts automatically:
- Read component name from JSON
- Find component directory (parent of script directory)
- Clone dependencies listed in JSON
- Copy headers from paths specified in JSON
- Build using build type specified in JSON
- Apply patches listed in JSON

---

### What Makes These Scripts Generic?

| Feature | Implementation |
|---------|----------------|
| ✅ No hardcoded paths | All from JSON/environment |
| ✅ No hardcoded names | Read from JSON |
| ✅ No hardcoded dependencies | Defined in JSON |
| ✅ No hardcoded builds | Type/options from JSON |
| ✅ Flexible build systems | Autotools/CMake/Meson/Custom |
| ✅ Configurable patches | All in JSON |

---

### Example: Migrating from Utopia to CcspPandM

```bash
# 1. Copy scripts to CcspPandM
cp -r utopia/cov_docker_script ccsp-p-and-m/

# 2. Create ccsp-p-and-m/cov_docker_script/component_config.json
# Update: component name, dependencies, build settings

# 3. Run build
cd ccsp-p-and-m/cov_docker_script
./common_external_build.sh
```

**Scripts remain unchanged - only JSON changes!**

---

### Complete Example: Component with All Features

**component_config.json:**

```json
{
  "dependencies": {
    "repos": [
      {
        "name": "rbus",
        "repo": "https://github.com/rdkcentral/rbus.git",
        "branch": "v2.7.0",
        "header_paths": [
          { "source": "include", "destination": "$HOME/usr/include/rdkb/rbus" }
        ],
        "build": {
          "type": "cmake",
          "build_dir": "build",
          "cmake_flags": "-DCMAKE_INSTALL_PREFIX=$HOME/usr"
        }
      },
      {
        "name": "common-library",
        "repo": "https://github.com/rdkcentral/common-library.git",
        "branch": "main",
        "header_paths": [
          { "source": "source/ccsp/include", "destination": "$HOME/usr/include/rdkb" }
        ],
        "source_patches": [
          {
            "file": "$HOME/usr/include/rdkb/ccsp_message_bus.h",
            "type": "replace",
            "search": "typedef struct _CCSP_MESSAGE_BUS_CONNECTION",
            "replace": "typedef struct DBusLoop DBusLoop;\n\ntypedef struct _CCSP_MESSAGE_BUS_CONNECTION"
          },
          {
            "file": "$HOME/usr/include/rdkb/custom_config.h",
            "type": "create",
            "content": "#ifndef CUSTOM_CONFIG_H\n#define CUSTOM_CONFIG_H\n#define CUSTOM_FEATURE_ENABLED\n#endif"
          }
        ],
        "build": {
          "type": "script",
          "script": "cov_docker_script/common_external_build.sh"
        }
      }
    ]
  },
  
  "native_component": {
    "name": "moca-agent",
    "include_path": "$HOME/usr/include/rdkb/",
    "lib_output_path": "$HOME/usr/local/lib/",
    "header_sources": [
      { "source": "source/include", "destination": "$HOME/usr/include/rdkb" }
    ],
    "pre_build_commands": [
      {
        "description": "Generate dm_pack_datamodel.c from XML",
        "command": "python3 $HOME/usr/include/rdkb/dm_pack_code_gen.py config/TR181-MoCA.XML source/MoCASsp/dm_pack_datamodel.c"
      }
    ],
    "build": {
      "type": "autotools",
      "configure_options_file": "cov_docker_script/configure_options.conf"
    }
  }
}
```

**configure_options.conf:**

```properties
# MoCA Agent Configure Options
[CPPFLAGS]
# Include paths
-I$HOME/usr/include/rdkb/
-I/usr/include/dbus-1.0

# Core system defines
-DSAFEC_DUMMY_API
-D_COSA_HAL_
-DCONFIG_SYSTEM_MOCA

# CCSP/Component defines
-DCCSP_SUPPORT_ENABLED
-D_CCSP_CWMP_TCP_CONNREQ_HANDLER

# Product/Platform defines
-D_XB6_PRODUCT_REQ_
-D_XB7_PRODUCT_REQ_

# Features
-DFEATURE_SUPPORT_WEBCONFIG
-DMOCA_HOME_ISOLATION

[CFLAGS]
-ffunction-sections
-fdata-sections
-fno-strict-aliasing

[LDFLAGS]
-L$HOME/usr/local/lib/
-Wl,--allow-shlib-undefined
```

**Build execution:**

```bash
cd /path/to/moca-agent/cov_docker_script
./common_external_build.sh
```

**What happens:**
1. Clones rbus and common-library repositories
2. Copies headers from dependencies
3. Applies patches to common-library headers
4. Builds rbus (cmake) and common-library (nested build script)
5. Copies component headers
6. Runs pre-build command (generates code from XML)
7. Reads configure options from configure_options.conf
8. Runs autotools build with all flags
9. Installs libraries to output path

---

## ⚖️ Governance & Rules

### Configuration Rules

| Rule | Status |
|------|--------|
| Only JSON files may be modified | ✅ Allowed |
| All dependencies must be declared | ✅ Required |
| Script modifications | ❌ Forbidden |

### Script Governance

- 🔒 Scripts are **generic, shared, and immutable**
- 🌐 Any script change must apply **globally** to all components
- 📝 Component-specific logic belongs in **JSON only**

### Standardization

| Benefit | Description |
|---------|-------------|
| ✅ Scalable Onboarding | Consistent process across components |
| ✅ Build Reproducibility | Same configuration = same results |
| ✅ Maintainability | Single source of truth in JSON |
| ✅ Quality Assurance | Automated validation via CI/CD |

### Key Principles

> **Native build validation enables Coverity integration.**
>
> Scripts are immutable; configuration is component-specific.

**This approach ensures:**
- Scalable Coverity onboarding
- Consistent build behavior
- Long-term maintainability across RDK-B components

---

## 🔗 References

### Docker RDK CI Repository

Docker image for consistent RDK-B native builds:
- **Repository:** https://github.com/rdkcentral/docker-rdk-ci
- **Official Image:** `ghcr.io/rdkcentral/docker-rdk-ci:latest`

### Native Build Reference Implementation

Complete example with cov_docker_script integration:
- **Component:** https://github.com/rdkcentral/moca-agent/tree/feature/cov_native_build
- **Scripts Directory:** https://github.com/rdkcentral/moca-agent/blob/feature/cov_native_build/cov_docker_script
- **README:** https://github.com/rdkcentral/moca-agent/blob/feature/cov_native_build/cov_docker_script/README.md

### GitHub Actions Workflow

Reference CI/CD workflow for native build validation:
- **Workflow:** https://github.com/rdkcentral/moca-agent/blob/feature/cov_native_build/.github/workflows/native-build.yml

### Component Configuration Examples

- **JSON Configuration:** https://github.com/rdkcentral/moca-agent/blob/feature/cov_native_build/cov_docker_script/component_config.json
- **Configure Options:** https://github.com/rdkcentral/moca-agent/blob/feature/cov_native_build/cov_docker_script/configure_options.conf

---

## 📄 License

This build system is part of the RDK-B project. See component repository for license details.

---

## 🤝 Contributing

For issues, improvements, or questions:

1. 🐛 **Issues** → Raise in component repository
2. 💡 **Script Changes** → Must apply globally to all components
3. 📝 **Documentation** → Update this README
4. 🐳 **Docker Changes** → Raise PR to [docker-rdk-ci](https://github.com/rdkcentral/docker-rdk-ci)

---

## 📞 Support

- **CMFSUPPORT Tickets** → For Coverity enablement
- **GitHub Issues** → For build system questions
- **Component Maintainers** → For component-specific issues

---

**Made with ❤️ for RDK-B Community**
