/**
 * The service worker, and what it deliberately is not.
 *
 * # Why this file exists at all, when the project refused one
 *
 * `src/lib/notifications.ts` refuses a service worker in as many words: "one would be a cache of
 * the application shell served by the same server the desktop build exists to stop trusting". That
 * objection is about **caching**. A worker that caches the shell keeps a copy of the application
 * alive across visits, so a server that served a hostile bundle once keeps its victim even after
 * it is fixed — which is a real and serious thing to refuse.
 *
 * This worker caches nothing. It registers no `fetch` handler, opens no `Cache`, keeps no
 * precache manifest, and intercepts no request. Every load of the page comes from the network
 * exactly as it did before this file existed, and deleting it changes nothing except that
 * notifications stop arriving. It cannot serve a stale application because it cannot serve an
 * application.
 *
 * The reason a worker is needed at all is that the Push API has no other delivery point: a push
 * message wakes the *worker*, not the page, and there is no version of Web Push that reaches a
 * document directly.
 *
 * # Why the text is a constant
 *
 * The worker cannot decrypt. The MLS keys live in a WASM module inside the page, in memory the
 * worker has no access to, and moving them here would mean handing the decryption keys to a
 * context that outlives every tab. So the notification says that something arrived, and nothing
 * about what: the same answer iOS forces on every messenger, arrived at here on purpose rather
 * than by constraint.
 *
 * That is also the third of the three limits in `migrations/0011_push.sql`: the wake-up carries
 * no text, no sender and no group id. There is nothing here to display even if this file wanted
 * to.
 */

// Kept in step with `NOTICE_TITLE` and `NOTICE_BODY_ONE` in `src/lib/notifications.ts`. Duplicated
// rather than imported: a service worker is its own module graph, served as a plain file so that
// what is deployed is what can be read, and a build step to share two strings would cost more
// clarity than it saves. `push.test.ts` pins them against their source.
const TITLE = "Whispee";
const BODY = "New message";

self.addEventListener("push", (event) => {
  // `waitUntil` or the worker may be killed before the notification is shown. Browsers also
  // require that a push handler show *something*: staying silent gets the subscription revoked
  // after a few offences, and on some browsers displays a "this site was updated in the
  // background" notice instead — worse than ours, and not ours to write.
  event.waitUntil(
    self.registration.showNotification(TITLE, {
      body: BODY,
      // The collapse key. Ten messages while the phone is in a pocket are one notification, not
      // ten — the page does the same with `tag: conversation`, except this side does not know
      // which conversation, so everything collapses into one.
      tag: "whispee-wake",
      // No `renotify`: the point of collapsing is not to buzz again for each one.
      silent: false,
    }),
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();

  // Focus a tab that is already open before opening another. Somebody who clicks a notification
  // wants the conversation they were already in, not a second copy of the application signing in
  // from scratch.
  event.waitUntil(
    (async () => {
      const clients = await self.clients.matchAll({
        type: "window",
        includeUncontrolled: true,
      });

      for (const client of clients) {
        if ("focus" in client) return client.focus();
      }

      // No deep link, and it is not an oversight: the wake-up does not say which conversation,
      // so the honest destination is the application's front door.
      return self.clients.openWindow("/");
    })(),
  );
});
