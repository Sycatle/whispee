/**
 * Padding an attachment is only worth anything if the file comes back byte for byte: a mistake
 * here does not weaken privacy, it destroys the file.
 *
 * The `Api` is a stub. What matters is the length of what would have been uploaded — that number
 * is precisely what the server sees, and the whole point of the exercise.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import type { Api } from "./api.ts";
import { MAX_ATTACHMENT_BYTES, downloadAndDecrypt, encryptAndUpload } from "./attachments.ts";

const GROUP = new Uint8Array([1, 2, 3]);

/** Keeps the blob in memory and remembers how many bytes crossed the wire. */
function stubApi() {
  const blobs = new Map<string, Uint8Array>();
  let next = 0;

  const api = {
    async uploadAttachment(_group: Uint8Array, ciphertext: Uint8Array) {
      const id = String((next += 1));
      blobs.set(id, ciphertext);
      return { id };
    },
    async downloadAttachment(_group: Uint8Array, id: string) {
      const found = blobs.get(id);
      if (!found) throw new Error(`unknown attachment ${id}`);
      return found;
    },
  };

  return { api: api as unknown as Api, size: (id: string) => blobs.get(id)!.length };
}

function fileOf(length: number, name = "x.bin"): File {
  const bytes = new Uint8Array(length).map((_, i) => (i * 31 + 7) % 256);
  return new File([bytes], name, { type: "application/octet-stream" });
}

test("a padded attachment comes back exactly as it went in", async () => {
  const { api } = stubApi();

  for (const length of [0, 1, 255, 256, 1024, 100_000]) {
    const file = fileOf(length);
    const ref = await encryptAndUpload(api, GROUP, file);
    const back = new Uint8Array(await (await downloadAndDecrypt(api, GROUP, ref)).arrayBuffer());
    assert.deepEqual(back, new Uint8Array(await file.arrayBuffer()), `length ${length}`);
    assert.equal(ref.size, length);
  }
});

/** The property the padding exists for: the server can no longer tell these files apart. */
test("files of different sizes upload as the same number of bytes", async () => {
  const { api, size } = stubApi();

  const uploaded = [];
  for (const length of [300_000, 400_000, 524_287]) {
    uploaded.push(size((await encryptAndUpload(api, GROUP, fileOf(length))).id));
  }

  assert.equal(new Set(uploaded).size, 1);
  assert.equal(uploaded[0], 524_288 + 16);
});

/**
 * Descriptors written before padding landed carry no flag, and must still open. Losing history
 * would be a worse regression than the leak this change closes.
 */
test("an attachment sent before padding is read unpadded", async () => {
  const { api } = stubApi();
  const ref = await encryptAndUpload(api, GROUP, fileOf(1000));

  // What an old sender produced: the same descriptor without the flag. Its blob is padded, so the
  // tail of zeroes is expected here — this checks the flag is what decides, nothing else.
  const raw = new Uint8Array(
    await (await downloadAndDecrypt(api, GROUP, { ...ref, padded: undefined })).arrayBuffer(),
  );
  assert.equal(raw.length, 1024);
  assert.equal(raw[1000], 0x80);
});

/**
 * The ceiling is the reason the top bucket exists. A file at the limit must still fit under what
 * the server accepts, tag included — this is the case a bucket that kept doubling would break.
 */
test("the largest allowed file still fits under the server ceiling", async () => {
  const { api, size } = stubApi();
  const ref = await encryptAndUpload(api, GROUP, fileOf(MAX_ATTACHMENT_BYTES));
  assert.equal(size(ref.id), 25 * 1024 * 1024);
});

test("a file above the limit is refused before anything is encrypted", async () => {
  const { api } = stubApi();
  await assert.rejects(
    () => encryptAndUpload(api, GROUP, fileOf(MAX_ATTACHMENT_BYTES + 1)),
    /too large/i,
  );
});
