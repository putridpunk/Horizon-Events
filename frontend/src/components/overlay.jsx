import { useEffect, useId, useRef } from "react";
import Icon from "./ui/Icon.jsx";

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/** Esc closes, focus moves into the dialog and comes back to the opener, and Tab never leaves it. */
function useOverlay(onClose, busy) {
  const ref = useRef(null);
  const closeRef = useRef(onClose);
  const busyRef = useRef(busy);
  closeRef.current = onClose;
  busyRef.current = busy;

  useEffect(() => {
    const opener = document.activeElement;
    const node = ref.current;
    node?.focus();
    function onKey(e) {
      if (e.key === "Escape" && !busyRef.current) {
        e.stopPropagation();
        closeRef.current();
      } else if (e.key === "Tab" && node) {
        const items = [...node.querySelectorAll(FOCUSABLE)];
        if (!items.length) { e.preventDefault(); return; }
        const first = items[0];
        const last = items[items.length - 1];
        if (!node.contains(document.activeElement)) { e.preventDefault(); first.focus(); }
        else if (e.shiftKey && (document.activeElement === first || document.activeElement === node)) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
      }
    }
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      if (opener instanceof HTMLElement && document.contains(opener)) opener.focus();
    };
  }, []);
  return ref;
}

/** A panel that slides in from the right, with a header that stays put while the body scrolls. */
export function Drawer({ title, subtitle, onClose, children }) {
  const titleId = useId();
  const ref = useOverlay(onClose, false);
  return (
    <div className="overlay" onClick={onClose}>
      <aside className="drawer" role="dialog" aria-modal="true" aria-labelledby={titleId} tabIndex={-1} ref={ref}
        onClick={(e) => e.stopPropagation()}>
        <header className="drawer-header">
          <div>
            <h2 id={titleId}>{title}</h2>
            {subtitle && <div className="muted">{subtitle}</div>}
          </div>
          <button className="icon-button" aria-label="Close" onClick={onClose}><Icon name="close" /></button>
        </header>
        <div className="drawer-body">{children}</div>
      </aside>
    </div>
  );
}

/** A centred dialog. While `busy` (a request is in flight) it cannot be dismissed. */
export function Modal({ title, onClose, busy = false, children }) {
  const titleId = useId();
  const ref = useOverlay(onClose, busy);
  return (
    <div className="overlay center" onClick={() => !busy && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby={titleId} tabIndex={-1} ref={ref}
        onClick={(e) => e.stopPropagation()}>
        <h2 id={titleId}>{title}</h2>
        {children}
      </div>
    </div>
  );
}
