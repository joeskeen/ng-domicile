import { Database } from "bun:sqlite";
import { describe, expect, it } from "bun:test";
import { createCipheriv, createHash, pbkdf2Sync } from "node:crypto";
import { mkdir, mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createSafeStorage } from "./electron/safe-storage";
import type { CookiesSetDetails } from "./electron/session-calls";
import { IMPORTED, importProfile } from "./import-profile";

// The app's own Electron on Domicile picks basic_text, so its cookies are v10.
const safeStorage = createSafeStorage({
  backend: () => "basic_text",
  password: () => ({ password: undefined }),
});

/** `plain` as Chromium's OSCrypt encrypts it with the v10 key. */
const v10 = (plain: Buffer) => {
  const key = pbkdf2Sync("peanuts", "saltysalt", 1, 16, "sha1");
  const cipher = createCipheriv("aes-128-cbc", key, Buffer.alloc(16, " "));
  return Buffer.concat([
    Buffer.from("v10"),
    cipher.update(plain),
    cipher.final(),
  ]);
};

/** Microseconds from 1601, as Chromium keeps times. */
const chromiumTime = (unixSeconds: number) =>
  BigInt(Math.round((unixSeconds + 11_644_473_600) * 1_000_000));

const NOW = Date.UTC(2026, 10, 16);

const profile = async () => {
  const dir = await mkdtemp(join(tmpdir(), "electron-host-import-"));
  const userData = join(dir, "Slack");
  await mkdir(join(userData, "Local Storage/leveldb"), { recursive: true });
  await writeFile(join(userData, "Local Storage/leveldb/000003.log"), "ls");
  await mkdir(join(userData, "Network"), { recursive: true });
  const db = new Database(join(userData, "Network/Cookies"));
  db.run("CREATE TABLE meta (key TEXT, value TEXT)");
  db.run("INSERT INTO meta VALUES ('version', '24')");
  db.run(
    "CREATE TABLE cookies (host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB, path TEXT, expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER, has_expires INTEGER, samesite INTEGER)",
  );
  const insert = db.prepare(
    "INSERT INTO cookies VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
  );
  // Version 24 encrypts the host's SHA-256 ahead of the value.
  const hostHash = createHash("sha256").update(".slack.com").digest();
  const encrypted = v10(Buffer.concat([hostHash, Buffer.from("xoxd-secret")]));
  insert.run(
    ".slack.com",
    "d",
    "",
    encrypted,
    "/",
    chromiumTime(NOW / 1000 + 86_400),
    1,
    1,
    1,
    0,
  );
  insert.run(
    "app.slack.com",
    "lang",
    "en",
    new Uint8Array(),
    "/",
    0,
    1,
    0,
    0,
    1,
  );
  insert.run(
    ".slack.com",
    "old",
    "x",
    new Uint8Array(),
    "/",
    chromiumTime(NOW / 1000 - 1),
    1,
    0,
    1,
    -1,
  );
  db.close();
  return { storage: join(dir, "engine/Storage/ext/domicile/AB"), userData };
};

const run = (
  storage: string | undefined,
  userData: string,
  set: CookiesSetDetails[],
) =>
  importProfile({
    decrypt: safeStorage.decryptBytes,
    now: () => NOW,
    setCookie: (details) => {
      set.push(details);
      return Promise.resolve();
    },
    storage,
    userData,
  });

describe(importProfile, () => {
  it("brings the app's site storage and cookies onto the engine, once", async () => {
    const { storage, userData } = await profile();
    const set: CookiesSetDetails[] = [];

    expect(await run(storage, userData, set)).toEqual({
      cookies: 2,
      skipped: 0,
      storage: ["Local Storage"],
    });
    expect(
      await readFile(join(storage, "Local Storage/leveldb/000003.log"), "utf8"),
    ).toBe("ls");
    expect(set).toEqual([
      {
        domain: ".slack.com",
        expirationDate: NOW / 1000 + 86_400,
        httpOnly: true,
        name: "d",
        path: "/",
        sameSite: "no_restriction",
        secure: true,
        url: "https://slack.com/",
        value: "xoxd-secret",
      },
      {
        httpOnly: false,
        name: "lang",
        path: "/",
        sameSite: "lax",
        secure: true,
        url: "https://app.slack.com/",
        value: "en",
      },
    ]);
    expect((await stat(join(storage, IMPORTED))).isFile()).toBe(true);

    expect(await run(storage, userData, [])).toBeUndefined();
  });

  it("replaces what the engine made of a run before the import", async () => {
    const { storage, userData } = await profile();
    await mkdir(join(storage, "Local Storage/leveldb"), { recursive: true });
    await writeFile(join(storage, "Local Storage/leveldb/signed-out"), "");

    await run(storage, userData, []);

    expect(
      await stat(join(storage, "Local Storage/leveldb/signed-out")).catch(
        () => undefined,
      ),
    ).toBeUndefined();
  });

  it("does nothing while the engine has the partition open", async () => {
    const { userData } = await profile();

    expect(await run(undefined, userData, [])).toBeUndefined();
  });

  it("marks a partition done when the app has no profile of its own", async () => {
    const { storage } = await profile();

    expect(await run(storage, join(storage, "nowhere"), [])).toEqual({
      cookies: 0,
      skipped: 0,
      storage: [],
    });
    expect((await stat(join(storage, IMPORTED))).isFile()).toBe(true);
  });
});
