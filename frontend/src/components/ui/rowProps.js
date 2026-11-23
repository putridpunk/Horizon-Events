/** Props that make a table row act like a button: focusable, opens on click, Enter or Space. */
export default function rowProps(onActivate) {
  return {
    className: "clickable",
    tabIndex: 0,
    onClick: onActivate,
    onKeyDown: (e) => {
      if ((e.key === "Enter" || e.key === " ") && e.target === e.currentTarget) {
        e.preventDefault();
        onActivate();
      }
    },
  };
}
