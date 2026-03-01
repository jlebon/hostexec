# hostexec

A proxy that allows sandboxed AI agents to interactively request running
commands in the host context using a tmux prompt.

## Motivation

We have pretty good (albeit fragmented) sandboxing solutions for AI agents
at this point centered around containerization. E.g. my AI agent can install
packages, run containers, and VMs, all in isolation from the host and any
sensitive files/secrets.

But sometimes you still want the agent to run commands in the host context,
whether to e.g. run a `gh` command for a write action, or to help debug
something happening on the host. This doesn't happen very often, so a manual
approval process is fine.

hostexec gives the agent a socket through which it can ask the host to run
commands. On the host side, the server listens for requests and interactively
asks permission to run the command (through a tmux prompt). A good sandboxed
environment covers 98% of AI agent usage. hostexec is for the other 2%.

More recently, hostexec also adds some additional tmux integration sugar (see
"Notifications" section).

## Installing

```
cargo install --path .
```

## Usage

### Manual testing

Within tmux, in one terminal, run:

```bash
SOCK_FILE=$(mktemp); echo $SOCK_FILE
hostexec serve --write-socket-path-to "$SOCK_FILE"
```

In another terminal, run:

```bash
HOSTEXEC_SOCKET=$(cat "$SOCK_FILE") hostexec run echo hello world
```

### Notifications

Apart from the primary goal of host command execution, hostexec also exposes a
`notify` subcommand which can be used by sandboxed agents to notify the host of
their current state through integration with tmux. Unlike `run`, `notify` does
not require user approval. Actions on the host side for each hook event are
hardcoded and detailed in the table below. The daemon uses `$TMUX_PANE` from its
environment to determine the pane it's in.

```bash
HOSTEXEC_SOCKET=$(cat "$SOCK_FILE") hostexec notify idle
```

Supported hooks:

| Hook | Effect |
|---|---|
| `session-start` | Add 🤖 prefix to window name |
| `busy` | Set window suffix to ⏳ |
| `idle` | Terminal bell + set window suffix to ✋ |
| `session-exit` | Restore original window name |

Unknown hook names are silently ignored.

See the [notification hooks](#notification-hooks) section for how to wire
this into your agent automatically.

### Integrating into your AI agent sandbox

You'd normally not manually run hostexec serve/run at all. Instead, you'd
integrate it into your agent sandboxing solution as follows:

1. Before starting a new sandbox, the harness runs `hostexec serve` e.g. as a
   background process or via systemd-run.
2. When creating the sandbox, pass in the socket path via the `HOSTEXEC_SOCKET`
   environment variable.
3. In your `AGENTS.md`, add lines like:

   > If you want to run something on the host or in the host context, use
   > `hostexec run <command> [args...]`. This will prompt the user for approval.

   You should now be able to ask your agent something like:

   > Run `ls` in the host context.

This also implies the `hostexec` binary is available in the sandbox. You could
mount it in or have it pre-installed in the container image.

#### Example usage for GitHub

My AI agent has access to a read-only GitHub token. My host has access to a
read-write GitHub token. So I also have this line in my `AGENTS.md`:

> For read-write `gh` operations (e.g. creating PRs, merging, commenting), run
> `gh` in the host context.

And that way, the agent can still do write-level things when needed.

If you're building an automated or CI workflow around GitHub, you probably want
to set up a dedicated GitHub user instead (or use service-gator; see below).

#### Notification hooks

Most coding agents support hooks or plugins that fire on lifecycle events. You
can use `hostexec notify <hook>` in these to update tmux window indicators and
get bell alerts on the host.

For example, with [OpenCode](https://opencode.ai/docs/plugins):

```js
// ~/.config/opencode/plugins/notify.js
export const NotifyPlugin = async ({ client, $ }) => {
  await $`hostexec notify session-start`;

  const isTopLevel = async (sessionID) => {
    const res = await client.session.get({ path: { id: sessionID } });
    return !res.data?.parentID;
  };

  return {
    "tool.execute.before": async (input, _output) => {
      if (input.tool !== "question" && input.tool !== "plan_exit") return;
      await $`hostexec notify idle`;
    },
    "tool.execute.after": async (input, _output) => {
      if (input.tool !== "question") return;
      await $`hostexec notify busy`;
    },
    event: async ({ event }) => {
      if (event.type === "global.disposed") {
        await $`hostexec notify session-exit`;
        return;
      }
      if (event.type !== "session.status") return;
      const { sessionID, status } = event.properties;
      if (!(await isTopLevel(sessionID))) return;
      if (status.type === "busy") {
        await $`hostexec notify busy`;
      } else if (status.type === "idle") {
        await $`hostexec notify idle`;
      }
    },
  };
};
```

Similar hook mechanisms exist in other agents (e.g. Claude Code hooks, Cursor
rules).

## Comparison with related projects

### vs host-spawn / flatpak-spawn

[host-spawn](https://github.com/1player/host-spawn) (and `flatpak-spawn --host`,
which it reimplements) lets a containerized process run commands on the host by
calling a D-Bus method served by the Flatpak session helper daemon on the host.

The main differences are:

1. There is no approval mechanism because host-spawn is not meant as a security
   boundary.
2. host-spawn uses D-Bus. hostexec uses a `SOCK_SEQPACKET` socket directly
   so it's easier to integrate into a container sandbox.

### vs service-gator

[service-gator](https://github.com/cgwalters/service-gator) solves a different
but related problem: giving sandboxed AI agents _scoped_ access to external
services like GitHub, GitLab, and JIRA. It does not execute arbitrary commands
on the host. Instead, it exposes a fixed set of tools via the MCP protocol over
HTTP.

The main differences are:

1. hostexec allows an AI agent to run any host commands. service-gator exposes
   a limited set of service-specific operations (e.g. creating PRs, pushing
   branches).
2. hostexec uses interactive per-command approval and so is geared towards the
   local developer experience. service-gator uses static scope configurations,
   and is designed to work both locally and in CI/CD infrastructure.

The two are complementary. service-gator allows "always-on" access to privileged
resources. hostexec allows "on-request" access to (potentially even more)
privileged resources.
