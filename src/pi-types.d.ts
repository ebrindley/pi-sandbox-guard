// Minimal ambient types for the subset of Pi's ExtensionAPI this guard uses.
// These mirror the documented pi-coding-agent contract; replace with the real
// `@mariozechner/pi-coding-agent` / `@earendil-works/pi-coding-agent` types when
// the package is available in the install environment.

export interface ToolCallEvent {
  type?: string;
  toolCallId?: string;
  toolName: string;
  /** Mutable per Pi docs; this guard NEVER mutates it. */
  input: { command?: string; cwd?: string; timeout?: number; [k: string]: unknown };
  cwd?: string;
}

export interface ExtensionUI {
  confirm(title: string, message: string): Promise<boolean>;
  notify(message: string, level?: 'info' | 'warning' | 'error'): void;
}

export interface ExtensionContext {
  ui?: ExtensionUI;
  cwd?: string;
  [k: string]: unknown;
}

/** Returned from a `tool_call` handler. Returning nothing/undefined = allow. */
export type ToolCallResult = { block?: boolean; reason?: string } | void | undefined;

export interface ExtensionAPI {
  on(
    type: 'tool_call',
    handler: (event: ToolCallEvent, ctx: ExtensionContext) => Promise<ToolCallResult> | ToolCallResult,
  ): void;
  on(type: string, handler: (event: unknown, ctx: ExtensionContext) => unknown): void;
  isToolCallEventType?(name: string, event: ToolCallEvent): boolean;
}

declare const extension: (pi: ExtensionAPI) => void;
export default extension;
