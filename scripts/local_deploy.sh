#!/bin/bash
# Local project launchers and refresh helpers.
# Sourced by deploy.sh; references SCRIPT_DIR, PROJECTS_DIR, LOG_DIR, PIDS.
#
# Each launcher uses a project-local runtime directory so no global language
# toolchain is modified or required on the host machine.

RBENV_LOCAL="$SCRIPT_DIR/.rbenv"   # Ruby — used by Flowers
NVM_LOCAL="$SCRIPT_DIR/.nvm"       # Node  — used by Labyrinth and Portfolio

# ----------------------------------------------------------
# Runtime bootstrap helpers
# ----------------------------------------------------------

setup_rbenv_local() {
    # On Debian/Ubuntu, check that the required dev headers are installed before
    # compiling Ruby from source. Missing headers produce a Ruby silently lacking
    # extensions (fiddle, psych, readline, zlib) with no clear error message.
    if command -v dpkg &>/dev/null; then
        local required_pkgs=(libssl-dev zlib1g-dev libreadline-dev libyaml-dev libffi-dev)
        local missing=()
        for pkg in "${required_pkgs[@]}"; do
            dpkg -l "$pkg" 2>/dev/null | grep -q "^ii" || missing+=("$pkg")
        done
        if [ ${#missing[@]} -gt 0 ]; then
            err "Missing system packages required to compile Ruby: ${missing[*]}
  Install them with:
    sudo apt install ${missing[*]}"
        fi
    fi

    if [ ! -d "$RBENV_LOCAL" ]; then
        log "Installing project-local rbenv..."
        git clone -q --depth 1 https://github.com/rbenv/rbenv.git "$RBENV_LOCAL"
        git clone -q --depth 1 https://github.com/rbenv/ruby-build.git "$RBENV_LOCAL/plugins/ruby-build"
    fi
    export RBENV_ROOT="$RBENV_LOCAL"
    export PATH="$RBENV_LOCAL/bin:$RBENV_LOCAL/shims:$PATH"
    # Tell ruby-build where Homebrew's zlib/openssl/readline live so the compiled
    # Ruby is complete. Without these flags, zlib (and others) are silently missing.
    if command -v brew &>/dev/null; then
        export RUBY_CONFIGURE_OPTS="\
--with-openssl-dir=$(brew --prefix openssl 2>/dev/null) \
--with-zlib-dir=$(brew --prefix zlib 2>/dev/null) \
--with-readline-dir=$(brew --prefix readline 2>/dev/null)"
    fi
    rbenv install --skip-existing
    rbenv rehash
}

setup_nvm_local() {
    export NVM_DIR="$NVM_LOCAL"
    if [ ! -s "$NVM_DIR/nvm.sh" ]; then
        log "Installing project-local nvm..."
        mkdir -p "$NVM_DIR"
        PROFILE=/dev/null curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
    fi
    # shellcheck source=/dev/null
    . "$NVM_DIR/nvm.sh"
}

# ----------------------------------------------------------
# Project launchers
# ----------------------------------------------------------

start_flowers_local() {
    local dir="$PROJECTS_DIR/RubyOnRails/Flowers"
    clone_if_missing "https://github.com/Siderskini/RubyOnRails.git" "RubyOnRails"
    cd "$dir"
    setup_rbenv_local
    local bundle_bin
    bundle_bin="$(rbenv which bundle)"
    "$bundle_bin" config set --local path vendor/bundle
    "$bundle_bin" install --quiet
    "$bundle_bin" exec rails db:migrate 2>/dev/null || true
    "$bundle_bin" exec rails db:seed 2>/dev/null || true
    log "Starting Flowers on port 3001..."
    "$bundle_bin" exec rails server -p 3001 -b 0.0.0.0 > "$LOG_DIR/flowers.log" 2>&1 &
    save_pid $! "flowers"; PIDS+=($!)
    save_host "http://localhost:3001" "flowers"
}

start_labyrinth_local() {
    local dir="$PROJECTS_DIR/Labyrinth"
    clone_if_missing "https://github.com/Siderskini/Labyrinth.git" "Labyrinth"
    cd "$dir"
    setup_nvm_local
    nvm install --lts
    npm install --silent
    if [ ! -f key.pem ] || [ ! -f cert.pem ]; then
        log "Generating SSL certs for Labyrinth..."
        openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
            -days 365 -nodes -subj "/CN=localhost" 2>/dev/null
    fi
    if grep -q "34.57.176.17" public/main.js 2>/dev/null; then
        log "Patching Labyrinth client IP..."
        sed -i '' 's/34\.57\.176\.17/localhost/g' public/main.js
    fi
    log "Starting Labyrinth on port 4000..."
    node index.js > "$LOG_DIR/labyrinth.log" 2>&1 &
    save_pid $! "labyrinth"; PIDS+=($!)
    save_host "https://localhost:4000" "labyrinth"
}

start_fishing_local() {
    local dir="$PROJECTS_DIR/LearningGo/fishing/web"
    clone_if_missing "https://github.com/Siderskini/LearningGo.git" "LearningGo"
    cd "$dir"
    log "Starting Fishing on port 8080..."
    python3 -m http.server 8080 > "$LOG_DIR/fishing.log" 2>&1 &
    save_pid $! "fishing"; PIDS+=($!)
    save_host "http://localhost:8080" "fishing"
}

start_portfolio_local() {
    cd "$SCRIPT_DIR"
    setup_nvm_local
    nvm install --lts
    npm install --silent
    log "Starting Portfolio on port 3000..."
    npm run dev > "$LOG_DIR/portfolio.log" 2>&1 &
    save_pid $! "portfolio"; PIDS+=($!)
    save_host "http://localhost:3000" "portfolio"
}

clone_if_missing() {
    local url="$1" dir="$2"
    if [ ! -d "$PROJECTS_DIR/$dir" ]; then
        log "Cloning $dir..."
        git clone "$url" "$PROJECTS_DIR/$dir"
    else
        warn "$dir already cloned, skipping."
    fi
}

# ----------------------------------------------------------
# Refresh a single local project
# ----------------------------------------------------------
refresh_local_project() {
    local id="$1"
    kill_project "$id"
    case "$id" in
        flowers)   start_flowers_local ;;
        labyrinth) start_labyrinth_local ;;
        fishing)   start_fishing_local ;;
        portfolio) start_portfolio_local ;;
        *) err "Unknown local project: $id" ;;
    esac
    log "$id refreshed locally."
}
