/**
 * Global trust / mode context for analyst consoles (read-only posture, no internal doc IDs in copy).
 */
export function SocContextStrip() {
  return (
    <div className="soc-context-strip" role="status" aria-live="polite">
      <span className="soc-context-strip__badge">Read only</span>
      <span className="soc-context-strip__text">
        This console is optimized for monitoring, investigation, and executive review. Operational decisions and policy
        changes continue through approved response workflows.
      </span>
    </div>
  );
}
