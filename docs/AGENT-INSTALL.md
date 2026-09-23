# Installing the Local Privacy Gateway with a coding agent

Copy the prompt below into a coding agent that can run shell commands in your home directory —
Claude Code, Codex, Cursor or anything comparable — and let it run. It installs the gateway, runs
the test suite, creates the configuration, installs the background proxy as a launchd agent
(macOS) or a systemd user unit (Linux), verifies it with local-only smoke tests, and appends one
shell function to your shell profile.

The prompt is self-contained: it states every default it needs, so the agent never has to stop and
ask. Read it before you run it — it installs a background service and edits your shell profile.

---

## The prompt

```text
You are installing the Local Privacy Gateway (https://github.com/j911si/local-privacy-gateway) on
this machine and verifying that it works. Complete the whole installation autonomously: do not ask
me any questions, use the defaults stated below for every decision, and report at the end.

ASSUMPTIONS AND DEFAULTS (use these, do not ask):
- Install directory: $PGW_HOME if that variable is set, otherwise ~/local-privacy-gateway.
- Proxy listen address: 127.0.0.1:8787.
- Gateway config directory: ~/.config/privacy-gateway. Vault data: ~/.local/share/privacy-gateway.
- Model default for the shell function: sonnet[1m]. The [1m] suffix is required, never drop it.
- OS detection: `uname -s` -> "Darwin" means macOS (use launchd), "Linux" means Linux (use a
  systemd user unit). Anything else: skip the service step and report it.
- Login type: if the environment variable ANTHROPIC_API_KEY is set and non-empty, the user has an
  API key, so leave PGW_PROXY_TRANSFORM_SYSTEM unset (full protection). If it is empty or unset,
  assume an OAuth/subscription login and set PGW_PROXY_TRANSFORM_SYSTEM=0, because Anthropic
  answers OAuth requests with a modified system prompt with HTTP 429.
- Do not modify any existing shell configuration except appending one clearly marked block to the
  user's shell rc file (~/.zshrc for zsh, ~/.bashrc for bash). Never edit or reorder existing lines.
- If any step fails, stop, do not improvise a workaround, and report exactly what failed with the
  command output.

SECURITY RULES (non-negotiable):
- Never write an API key, token or password into any file, and never echo one.
- Never set PGW_PROXY_DEBUG_ORIGINALS. It writes untransformed prompts to disk in clear text.
- Never read, print, copy or back up ~/.config/privacy-gateway/vault.key or any vault.db.
- Never send a request to api.anthropic.com as part of this installation. All smoke tests are local.
- If a test fails, report it. Do not edit, skip or weaken tests to make them pass.

STEPS:

1. Check prerequisites.
   - `git --version` must succeed. If git is missing, install it (macOS: `xcode-select --install`
     or `brew install git`; Linux: the distribution package manager) and re-check.
   - `uv --version` must succeed. If uv is missing, install it with
     `curl -LsSf https://astral.sh/uv/install.sh | sh` (or `brew install uv` on macOS if brew is
     present), then make sure the uv binary is on PATH for this session
     (`export PATH="$HOME/.local/bin:$PATH"`) and re-check.
   - uv provides the Python interpreter; the project requires Python >= 3.12. You do not need a
     system Python.

2. Clone the repository into the install directory. If the directory already exists and is a git
   checkout of this repository, run `git pull --ff-only` instead of cloning. If it exists and is
   something else, stop and report.
   `git clone https://github.com/j911si/local-privacy-gateway.git <install dir>`

3. Install dependencies from the install directory:
   `uv sync --group proxy`
   Expected: uv resolves and installs; the packages starlette, uvicorn and httpx appear.

4. Run the test suite: `uv run pytest -q`
   Expected: the last line reports passed tests and contains no "failed" and no "error".
   If anything failed, STOP here and report the failing output. Do not continue.

5. Create the configuration directory and a starter config.
   - `mkdir -p ~/.config/privacy-gateway && chmod 700 ~/.config/privacy-gateway`
   - `mkdir -p ~/.local/share/privacy-gateway && chmod 700 ~/.local/share/privacy-gateway`
   - Create the three empty dictionary files ~/.config/privacy-gateway/customers.txt,
     domains.txt and hostnames.txt, each containing only the comment line
     "# one term per line", and chmod 600 each of them.
   - Write ~/.config/privacy-gateway/config.yaml with mode 600 and exactly this content:

       dictionaries:
         files:
           CUSTOMER_NAME: ./customers.txt
           INTERNAL_DOMAIN: ./domains.txt
           HOSTNAME: ./hostnames.txt

       restore:
         mode: lenient

     If config.yaml already exists, do not overwrite it; leave it alone and note this in the report.

6. First run, which creates the vault key. From the install directory:
   `uv run pgw pseudonymize tests/fixtures/customer_letter_de.txt`
   Expected on stdout: the letter with tokens such as <ORGANIZATION_NAME_001>, <ADDRESS_001>,
   <PERSON_FEMALE_001>, <CUSTOMER_ID_001>, <IBAN_001>, <PHONE_001>, <EMAIL_001>. On stderr a line
   "session: <32 hex characters>". Exit code 0.
   Then verify with `ls -l ~/.config/privacy-gateway/vault.key` that the key file exists with mode
   -rw------- (0600). Do not print its content.

7. Install the background service.
   macOS: from the install directory run
     `PGW_PROXY_TRANSFORM_SYSTEM=0 uv run pgw-proxy install-launchd`
     (omit the PGW_PROXY_TRANSFORM_SYSTEM prefix if ANTHROPIC_API_KEY was set, see assumptions).
     Expected output: "installed /Users/<you>/Library/LaunchAgents/com.privacy-gateway.proxy.plist",
     a list of the PGW_* variables taken over, the log directory, and a line
     "export ANTHROPIC_BASE_URL=http://127.0.0.1:8787".
   Linux: write ~/.config/systemd/user/privacy-gateway.service with this content, substituting the
   real home directory and the absolute path of uv from `command -v uv`:

       [Unit]
       Description=Local Privacy Gateway proxy
       After=network.target

       [Service]
       Type=simple
       WorkingDirectory=<install dir>
       ExecStart=<absolute uv path> run --project <install dir> pgw-proxy serve
       Restart=always
       RestartSec=2
       Environment=PATH=<dirname of uv>:/usr/local/bin:/usr/bin:/bin
       Environment=PGW_PROXY_LISTEN=127.0.0.1:8787
       Environment=PGW_PROXY_UPSTREAM=https://api.anthropic.com
       Environment=PGW_PROXY_TRANSFORM_SYSTEM=0

       [Install]
       WantedBy=default.target

     Omit the PGW_PROXY_TRANSFORM_SYSTEM line if ANTHROPIC_API_KEY was set. Then run
     `systemctl --user daemon-reload` and `systemctl --user enable --now privacy-gateway.service`.
   If neither service manager is available, skip this step, and in the report tell the user to run
   `uv run pgw-proxy serve --listen 127.0.0.1:8787` in the foreground instead.

8. Check the status.
   `uv run pgw-proxy status`
   Expected: the label, the plist path, "loaded: yes" on macOS, and
   "listening on 127.0.0.1:8787: yes". Exit code 0. On Linux use
   `systemctl --user status privacy-gateway.service` plus
   `uv run pgw-proxy status --listen 127.0.0.1:8787` (which will report loaded: no, that is correct
   there, only the listening line matters).
   If the port does not answer, read the log (macOS:
   ~/Library/Logs/privacy-gateway/com.privacy-gateway.proxy.err.log; Linux:
   `journalctl --user -u privacy-gateway.service -n 50`) and report.

9. Local smoke tests. No request reaches Anthropic in any of these.
   a) `curl -s http://127.0.0.1:8787/health`
      Expected exactly: {"status":"ok"}
   b) `curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8787/v1/messages \
         -H 'content-type: application/json' -d 'not json'`
      Expected: 422
   c) `curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8787/v1/messages \
         -H 'Host: evil.example' -H 'content-type: application/json' -d '{}'`
      Expected: 403
   If a code differs, report the actual code and the response body; do not change the code to make
   it match.

10. Append the shell function. Detect the shell from $SHELL (zsh -> ~/.zshrc, bash -> ~/.bashrc;
    if neither, report and skip). If the marker "# >>> local-privacy-gateway >>>" is already
    present, replace the block between the markers instead of appending a second one. Append:

        # >>> local-privacy-gateway >>>
        claude-private() {
          ANTHROPIC_BASE_URL=http://127.0.0.1:8787 \
          command claude --model "sonnet[1m]" "$@"
        }
        # <<< local-privacy-gateway <<<

11. Final report. Print, in this order:
    - Installed version and commit hash (`git -C <install dir> rev-parse --short HEAD`).
    - The install directory, the config file, the vault database path and the vault key path.
    - Whether PGW_PROXY_TRANSFORM_SYSTEM=0 was set, and the one-sentence reason.
    - The result of every smoke test with its actual status code.
    - How to use it: open a new shell and run `claude-private`.
    - Where the audit log is and how to watch it
      (`tail -f ~/.local/share/privacy-gateway/audit.jsonl`).
    - Uninstall instructions: macOS `uv run pgw-proxy uninstall-launchd`; Linux
      `systemctl --user disable --now privacy-gateway.service` and delete the unit file; then
      remove the block between the shell markers, delete the install directory, and — only if the
      user wants to discard every stored mapping — delete ~/.local/share/privacy-gateway and
      ~/.config/privacy-gateway.
    - Anything you skipped or that failed, stated plainly.
```

---

## What the agent will do

1. **Prerequisites** — checks `git` and `uv`, installs `uv` via the official installer or Homebrew
   if it is missing. `uv` supplies the Python 3.12+ interpreter, so no system Python is needed.
2. **Clone** into `~/local-privacy-gateway` (or `$PGW_HOME`), or fast-forward an existing checkout.
3. **Install** with `uv sync --group proxy`, which adds `starlette`, `uvicorn` and `httpx` on top of
   the core `cryptography` and `pyyaml`.
4. **Test** with `uv run pytest -q`. A failure stops the installation — the agent is explicitly
   told not to touch the tests.
5. **Configure** — creates `~/.config/privacy-gateway` and `~/.local/share/privacy-gateway` with
   mode `0700`, a `config.yaml` with mode `0600` that wires up three empty dictionary files for
   customer names, internal domains and hostnames, and sets `restore.mode: lenient` so a
   placeholder the model invented cannot abort an answer. An existing `config.yaml` is left alone.
6. **First run** on the bundled fixture, which creates the 32-byte vault key at
   `~/.config/privacy-gateway/vault.key` with mode `0600`. The agent verifies the mode but never
   reads the key.
7. **Service** — `pgw-proxy install-launchd` on macOS (plist
   `~/Library/LaunchAgents/com.privacy-gateway.proxy.plist`, `RunAtLoad` and `KeepAlive`, logs in
   `~/Library/Logs/privacy-gateway/`), or a systemd user unit on Linux. Sets
   `PGW_PROXY_TRANSFORM_SYSTEM=0` only when no `ANTHROPIC_API_KEY` is present, because an OAuth
   login answers a modified system prompt with HTTP 429.
8. **Verify** — `pgw-proxy status` plus three local calls: `/health` must return
   `{"status":"ok"}`, a `POST /v1/messages` with a non-JSON body must return **422**, and the same
   call with `Host: evil.example` must return **403**. None of them reach Anthropic.
9. **Shell function** — appends a `claude-private` function between
   `# >>> local-privacy-gateway >>>` markers, so it can be found and removed again. Nothing else in
   your shell profile is touched.

What it will never do: write a credential to disk, enable `PGW_PROXY_DEBUG_ORIGINALS` (which dumps
untransformed prompts in clear text), read or copy the vault key or database, send a request to
`api.anthropic.com`, or modify a test to make it pass.

## After installation

```bash
exec $SHELL          # pick up the new shell function
claude-private       # Claude Code through the proxy, with the 1M context window
```

Check that it is actually running through the proxy:

```bash
tail -f ~/.local/share/privacy-gateway/audit.jsonl
```

Every request produces one `proxy_request` line with the session key, the number of transformed
fields, the token count and the leak result — never any content.

Next steps:

- Fill `~/.config/privacy-gateway/customers.txt`, `domains.txt` and `hostnames.txt` with the names
  that matter to you, one per line. Rule-based detection cannot find a customer name or an internal
  hostname on its own; dictionaries are what makes those work. The files are read at startup, so
  restart the service after editing them (macOS:
  `launchctl kickstart -k gui/$UID/com.privacy-gateway.proxy`; Linux:
  `systemctl --user restart privacy-gateway.service`).
- Run `pgw validate <a real document>` to see what the current rules find in your own material, and
  add `context_words` or patterns for what they miss.
- Read the [security model and known limits](../README.md#security-model-and-known-limits) in the
  README. In particular: with an OAuth login the system prompt is **not** transformed, images and
  PDFs are never scanned, and there is no auth token on the proxy port.

Uninstall:

```bash
# macOS
uv run pgw-proxy uninstall-launchd
# Linux
systemctl --user disable --now privacy-gateway.service
rm ~/.config/systemd/user/privacy-gateway.service && systemctl --user daemon-reload

# both: remove the block between the markers in ~/.zshrc or ~/.bashrc, then
rm -rf ~/local-privacy-gateway

# only if you want to discard every stored token mapping as well:
rm -rf ~/.local/share/privacy-gateway ~/.config/privacy-gateway
```
