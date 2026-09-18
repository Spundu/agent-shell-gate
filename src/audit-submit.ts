import { appendFileSync } from 'node:fs';
import type { AuditDraft } from './audit/index.js';

// How the hook submits an audit event. The hook holds NO sealing key — it submits the
// UNSEALED draft to the WRITER (the Supervisor in Ring 1), which stamps `producer`, assigns
// the sequence, and seals it. In production this is an hvsocket + boot-MAC channel (Phase 1b);
// the file outbox below is the local/dev stand-in the writer drains.

export type AuditSubmit = (draft: AuditDraft) => boolean;

/**
 * Append the unsealed draft as one JSON line to the outbox the writer drains. The LEADING newline
 * (F13) guarantees the record starts on a fresh line, so a preceding newline-less forged partial
 * (a same-user process can prepend bytes) cannot fuse with and skip this honest record — it is
 * isolated as its own line and quarantined, while this record still seals. Blank lines are dropped
 * by the drain's trim filter.
 */
export function outboxSubmit(outboxPath: string): AuditSubmit {
  return (draft) => {
    try {
      appendFileSync(outboxPath, `\n${JSON.stringify(draft)}\n`, 'utf8');
      return true;
    } catch {
      return false;
    }
  };
}
