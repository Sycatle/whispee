/**
 * The popup asks the service worker to check, and reports what came back.
 *
 * It holds no logic of its own on purpose: the comparison lives in `verify.js`, where it is
 * testable, and the fetching lives in `background.js`, where the permissions are. A popup that
 * duplicated either would be a second implementation to keep honest.
 */
const answer = document.querySelector("#answer");
const detail = document.querySelector("#detail");

/**
 * Host access is requested here, at a click, and never declared up front.
 *
 * An extension that could read every site from the moment it is installed is a worse thing than
 * the problem it solves. The user points it at their own deployment, once, and Chrome remembers.
 */
async function permitted(origin) {
  return await chrome.permissions.request({ origins: [`${origin}/*`] });
}

document.querySelector("#run").addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) return;

  const origin = new URL(tab.url).origin;

  answer.className = "unknown";
  answer.textContent = "Checking…";
  detail.textContent = "";

  if (!(await permitted(origin))) {
    answer.textContent = "Not checked — access to this site was declined";
    return;
  }

  const result = await chrome.runtime.sendMessage({ kind: "check", tabId: tab.id, origin });

  answer.className = result.answer;
  answer.textContent =
    result.answer === "ok"
      ? `Every file matches ${result.tag}`
      : result.answer === "failed"
        ? "This page is not the published build"
        : `Could not check: ${result.error ?? "unknown"}`;

  const wrong = (result.findings ?? []).filter((finding) => finding.state !== "matched");
  if (wrong.length > 0) {
    const list = document.createElement("ul");
    for (const finding of wrong.slice(0, 12)) {
      const item = document.createElement("li");
      item.textContent = `${finding.state}: ${finding.path ?? finding.url}`;
      list.append(item);
    }
    detail.append(list);
  }

  if (result.answer === "ok") {
    const note = document.createElement("p");
    // Said on success, where somebody is most likely to over-read the result.
    note.textContent =
      "This says the files match the manifest GitHub published. It does not say this server " +
      "sends the same files to somebody else.";
    detail.append(note);
  }
});
