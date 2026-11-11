// Page-wide pieces both views share: toasts, the confirm dialog, copying to the clipboard.

import { byId, h, icon } from "./dom.ts";

export type Tone = "ok" | "bad" | "info" | "warn";

const toasts = byId<HTMLElement>("toasts");
const confirmDialog = byId<HTMLDialogElement>("confirm");
const confirmTitle = byId<HTMLElement>("confirm-title");
const confirmText = byId<HTMLElement>("confirm-text");
const confirmOk = byId<HTMLButtonElement>("confirm-ok");

/** A short note in the corner (an `aria-live` region): an op's answer, a refusal, a change. */
export function toast(tone: Tone, title: string, detail = ""): void {
  const close = h("button", { class: "toast-close", type: "button", "aria-label": "Dismiss" }, icon("x"));
  const node = h(
    "div",
    { class: `toast tone-${tone}` },
    h("span", { class: "toast-icon" }, icon(tone === "ok" ? "check" : tone === "bad" ? "ban" : tone === "warn" ? "timer" : "info")),
    h("div", { class: "toast-body" }, h("strong", {}, title), detail === "" ? null : h("span", { class: "toast-detail" }, detail)),
    close,
  );
  const remove = (): void => {
    node.classList.add("leaving");
    window.setTimeout(() => node.remove(), 200);
  };
  close.addEventListener("click", remove);
  toasts.append(node);
  while (toasts.children.length > 5) {
    toasts.firstElementChild?.remove();
  }
  window.setTimeout(remove, tone === "bad" ? 9000 : 5000);
}

/** Asks before something that can't be undone; true when confirmed. */
export function confirmAction(title: string, text: string, okLabel: string): Promise<boolean> {
  confirmTitle.textContent = title;
  confirmText.textContent = text;
  confirmOk.textContent = okLabel;
  confirmDialog.returnValue = "";
  return new Promise((resolve) => {
    confirmDialog.addEventListener("close", () => resolve(confirmDialog.returnValue === "ok"), { once: true });
    confirmDialog.showModal();
  });
}

/** Copies text; falls back to a hidden text area where the clipboard API isn't allowed (plain http). */
export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const area = h("textarea", { class: "sr-only", "aria-hidden": "true", readonly: true });
    area.value = text;
    document.body.append(area);
    area.focus();
    area.select();
    let done = false;
    try {
      done = document.execCommand("copy");
    } catch {
      done = false;
    }
    area.remove();
    return done;
  }
}

/** A button that copies `text` and says so. */
export function copyButton(text: string, label: string): HTMLButtonElement {
  const button = h("button", { type: "button", class: "btn small copy", "aria-label": label }, icon("copy", "icon tiny"), h("span", {}, "Copy"));
  button.addEventListener("click", () => {
    void copyText(text).then((ok) => {
      const span = button.querySelector("span:last-child");
      if (span !== null) span.textContent = ok ? "Copied" : "Copy failed";
      button.classList.toggle("copied", ok);
      window.setTimeout(() => {
        if (span !== null) span.textContent = "Copy";
        button.classList.remove("copied");
      }, 1600);
      if (!ok) toast("bad", "Couldn't copy", "Select the text and copy it by hand.");
    });
  });
  return button;
}
