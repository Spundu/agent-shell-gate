// Claude Code hook I/O contract (the external-command hook protocol). The CLI invokes the
// hook as a fresh process, passes a HookInput JSON on stdin, and reads a decision JSON on
// stdout. Anything self-declared here (esp. `agent`) is UNTRUSTED — recorded, never trusted
// for authorization.

export interface HookAgentContext {
  name?: string;
  kind?: 'main' | 'subagent' | 'vault';
  parent?: string;
  depth?: number;
}

export interface HookInput {
  hook_event_name: string;
  tool_name: string;
  tool_input?: Record<string, unknown>;
  tool_response?: unknown;
  session_id?: string;
  transcript_path?: string;
  cwd?: string;
  agent?: HookAgentContext;
}

export type PermissionDecision = 'allow' | 'ask' | 'deny';

export interface PreToolUseOutput {
  hookSpecificOutput: {
    hookEventName: 'PreToolUse';
    permissionDecision: PermissionDecision;
    permissionDecisionReason: string;
  };
  continue: boolean;
}

export interface PassThroughOutput {
  continue: boolean;
}

export type HookOutput = PreToolUseOutput | PassThroughOutput;

export function isPreToolUseOutput(out: HookOutput): out is PreToolUseOutput {
  return 'hookSpecificOutput' in out;
}
