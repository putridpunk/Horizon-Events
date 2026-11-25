const ATTRIBUTES = ["placeholder", "title", "aria-label", "alt"];
const SKIP_TAGS = new Set(["SCRIPT", "STYLE", "TEXTAREA", "CODE", "PRE"]);

function skipped(node) {
  for (let el = node.nodeType === 1 ? node : node.parentElement; el; el = el.parentElement) {
    if (SKIP_TAGS.has(el.tagName) || el.getAttribute?.("translate") === "no") return true;
  }
  return false;
}

function translateTextNode(node, translate) {
  const next = translate(node.nodeValue);
  if (next !== node.nodeValue && !skipped(node)) node.nodeValue = next;
}

function translateAttributes(el, translate) {
  for (const name of ATTRIBUTES) {
    const value = el.getAttribute?.(name);
    if (value) {
      const next = translate(value);
      if (next !== value) el.setAttribute(name, next);
    }
  }
}

/** Translate everything under `root` (text and a few attributes). */
export function translateTree(root, translate) {
  if (root.nodeType === 3) return translateTextNode(root, translate);
  if (root.nodeType !== 1) return undefined;
  translateAttributes(root, translate);
  const walker = root.ownerDocument.createTreeWalker(root, 1 | 4);  // elements and text
  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    if (node.nodeType === 3) translateTextNode(node, translate);
    else translateAttributes(node, translate);
  }
  return undefined;
}

/** Translate the document now and keep translating whatever React adds or changes. Returns a function that stops. */
export function startTranslating(doc, translate) {
  translateTree(doc.body, translate);
  doc.title = translate(doc.title);
  const observer = new MutationObserver((records) => {
    for (const record of records) {
      if (record.type === "characterData") translateTextNode(record.target, translate);
      else if (record.type === "attributes") translateAttributes(record.target, translate);
      else record.addedNodes.forEach((node) => translateTree(node, translate));
    }
  });
  observer.observe(doc.body, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ATTRIBUTES });
  return () => observer.disconnect();
}
