// Brings an app's sign-ins from its own Electron's profile into its partition
// on the engine, once, before its first window there: its site storage as
// files, and its cookies through the engine, decrypted with the app's own
// safeStorage key. See "Sign-ins" in docs/architecture/ELECTRON-APPS.md.

import { Database } from "bun:sqlite";
import {
  access,
  copyFile,
  cp,
  mkdir,
  mkdtemp,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { CookiesSetDetails } from "./electron/session-calls";

/** The site storage Chromium keeps as files in a profile, by directory. */
const SITE_STORAGE = ["Local Storage", "IndexedDB", "WebStorage"] as const;

/** Written in the partition once its import is done, so it's done once. */
export const IMPORTED = ".domicile-imported-from-electron";

/** Seconds from 1601, where Chromium's times start, to 1970. */
const WINDOWS_EPOCH = 11_644_473_600;

/** Chromium's `samesite` column, by its number. */
const SAME_SITES: Record<number, CookiesSetDetails["sameSite"]> = {
  [-1]: "unspecified",
  0: "no_restriction",
  1: "lax",
  2: "strict",
};

export type ImportDependencies = {
  /** The app's own Electron profile: its `userData`. */
  readonly userData: string;
  /** The app's partition on the engine, while nothing has opened it. */
  readonly storage: string | undefined;
  /** Sets a cookie in the app's partition on the engine. */
  readonly setCookie: (details: CookiesSetDetails) => Promise<void>;
  /** A cookie's value as the app's own safeStorage decrypts it, as bytes. */
  readonly decrypt: (encrypted: Buffer) => Buffer;
  readonly now: () => number;
};

/** What an import brought over. */
export type Imported = {
  readonly storage: readonly string[];
  readonly cookies: number;
  /** Cookies that didn't decrypt or that the engine refused. */
  readonly skipped: number;
};

const exists = (path: string) =>
  access(path).then(
    () => true,
    () => false,
  );

/**
 * Imports `userData` into `storage` unless it was done before or the engine
 * has the partition open. Undefined when there was nothing to do.
 */
export const importProfile = async ({
  decrypt,
  now,
  setCookie,
  storage,
  userData,
}: ImportDependencies): Promise<Imported | undefined> => {
  if (storage === undefined || (await exists(join(storage, IMPORTED)))) {
    return undefined;
  }
  await mkdir(storage, { recursive: true });
  const copied: string[] = [];
  for (const name of SITE_STORAGE) {
    const from = join(userData, name);
    if (await exists(from)) {
      // What the engine made of it before (a run signed out) gives way.
      await rm(join(storage, name), { force: true, recursive: true });
      await cp(from, join(storage, name), { recursive: true });
      copied.push(name);
    }
  }
  const { cookies, skipped } = await importCookies(
    userData,
    decrypt,
    setCookie,
    now,
  );
  await writeFile(join(storage, IMPORTED), "");
  return { cookies, skipped, storage: copied };
};

type CookieRow = {
  readonly host_key: string;
  readonly name: string;
  readonly value: string;
  readonly encrypted_value: Uint8Array;
  readonly path: string;
  readonly expires_utc: number | bigint;
  readonly is_secure: number;
  readonly is_httponly: number;
  readonly has_expires: number;
  readonly samesite: number;
};

const importCookies = async (
  userData: string,
  decrypt: ImportDependencies["decrypt"],
  setCookie: ImportDependencies["setCookie"],
  now: () => number,
) => {
  const candidates = [
    join(userData, "Network/Cookies"),
    join(userData, "Cookies"),
  ];
  let database: string | undefined;
  for (const candidate of candidates) {
    if (await exists(candidate)) {
      database = candidate;
      break;
    }
  }
  if (database === undefined) {
    return { cookies: 0, skipped: 0 };
  }
  // A copy, as the app's own Electron may hold the database open.
  const scratch = await mkdtemp(join(tmpdir(), "electron-host-cookies-"));
  try {
    const copy = join(scratch, "Cookies");
    await copyFile(database, copy);
    for (const journal of ["-wal", "-journal"]) {
      if (await exists(`${database}${journal}`)) {
        await copyFile(`${database}${journal}`, `${copy}${journal}`);
      }
    }
    const db = new Database(copy);
    try {
      const version = Number(
        (
          db.query("SELECT value FROM meta WHERE key = 'version'").get() as {
            value: string;
          } | null
        )?.value ?? 0,
      );
      const rows = db
        .query(
          "SELECT host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly, has_expires, samesite FROM cookies",
        )
        .all() as CookieRow[];
      let cookies = 0;
      let skipped = 0;
      for (const row of rows) {
        const details = cookieDetails(row, version, decrypt, now());
        if (details === "expired") {
          continue;
        }
        if (details === undefined) {
          skipped++;
          continue;
        }
        try {
          await setCookie(details);
          cookies++;
        } catch {
          skipped++;
        }
      }
      return { cookies, skipped };
    } finally {
      db.close();
    }
  } finally {
    await rm(scratch, { force: true, recursive: true });
  }
};

/** `row` as cookies.set takes it, "expired", or undefined if it won't decrypt. */
export const cookieDetails = (
  row: CookieRow,
  version: number,
  decrypt: ImportDependencies["decrypt"],
  now: number,
): CookiesSetDetails | "expired" | undefined => {
  const expires =
    row.has_expires === 1
      ? Number(row.expires_utc) / 1_000_000 - WINDOWS_EPOCH
      : undefined;
  if (expires !== undefined && expires * 1000 <= now) {
    return "expired";
  }
  let value = row.value;
  if (value === "" && row.encrypted_value.length > 0) {
    try {
      const plain = decrypt(Buffer.from(row.encrypted_value));
      // From version 24, the plain text starts with the SHA-256 of its host.
      value = (version >= 24 ? plain.subarray(32) : plain).toString("utf8");
    } catch {
      return undefined;
    }
  }
  const host = row.host_key.replace(/^\./, "");
  return {
    httpOnly: row.is_httponly === 1,
    name: row.name,
    path: row.path,
    sameSite: SAME_SITES[row.samesite] ?? "unspecified",
    secure: row.is_secure === 1,
    url: `${row.is_secure === 1 ? "https" : "http"}://${host}${row.path}`,
    value,
    ...(row.host_key.startsWith(".") ? { domain: row.host_key } : {}),
    ...(expires === undefined ? {} : { expirationDate: expires }),
  };
};
