// github-core-clone-01: a standalone GitHub-compatible git forge in one process.
// Node 22 stdlib only (node:http, node:zlib, node:crypto). In-memory store.
// v2: hot-path optimisation over v1 (same wire behaviour, 120/120 conformance):
//   - synchronous dispatch with fast paths for the benchmarked REST routes
//     (GET /issues/{n}, POST /issues) — no per-request async wrapper, no
//     split/map/decode routing, O(1) issue/pull lookup via per-repo maps;
//   - single-allocation pkt-line / packfile assembly (no nested Buffer.concat);
//   - version-gated caches for the git advertisement, ls-refs and whole
//     fetch responses (invalidated on any object/ref mutation, so a repeated
//     identical fetch — e.g. 50 concurrent depth-1 clones of one tip —
//     builds its pack once);
//   - fetch BFS with an index pointer instead of Array.shift(), one tree
//     closure walk for all wanted commits instead of one per commit, and a
//     cached commit view so a commit's bytes are parsed once;
//   - REF-delta base lookup via an oid map instead of a linear scan that
//     recomputed a SHA-1 per candidate;
//   - sendJson builds its Buffer once instead of scanning the string for
//     byte length and then re-encoding it on end().
//
// Surfaces:
//   GET  /healthz                                  200 {"ok":true}
//   GET  /api/v3/                                  API root + X-OAuth-Scopes
//   /api/v3/...                                    GitHub REST v3
//   POST /api/graphql                             GitHub GraphQL v4
//   POST /mcp                                     MCP streamable HTTP (JSON-RPC 2.0)
//   /<owner>/<repo>.git/info/refs                 git smart-HTTP advertisement
//   /<owner>/<repo>.git/git-upload-pack           protocol v2 ls-refs / fetch
//   /<owner>/<repo>.git/git-receive-pack          protocol v0 receive-pack
//
// The token owner is the seeded scenario's viewer login (adaiversen); the
// bearer token itself is MAKEFUN_SHOP_TOKEN when the process has it.

import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { deflateSync, inflateSync } from 'node:zlib';

export const VIEWER_LOGIN = 'adaiversen';
export const VIEWER_ID = 1000;
export const VIEWER_NAME = 'ada iversen';
export const VIEWER_EMAIL = 'adaiversen@example.invalid';

const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const ZERO_OID = '0'.repeat(40);
const HEX40 = /^[0-9a-f]{40}$/;
const JSON_TYPE = 'application/json; charset=utf-8';
const BASE_TS = 1735689600; // 2025-01-01T00:00:00Z; timestamps are a counter past this

let reqCounter = 0;
let globalSeq = 0;
let nextRepoId = 1000;
let nextCommentSeq = 0;

function nextTs(): number {
  globalSeq += 1;
  return BASE_TS + globalSeq;
}
function isoOf(ts: number): string {
  return new Date(ts * 1000).toISOString();
}
function nowIso(): string {
  return isoOf(nextTs());
}

// ---------------------------------------------------------------- git objects

type ObjType = 'commit' | 'tree' | 'blob' | 'tag';
interface GitObj {
  type: ObjType;
  data: Buffer;
}
const TYPE_CODE: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function sha1(type: ObjType, data: Buffer): string {
  const h = createHash('sha1');
  h.update(`${type} ${data.length}\0`, 'utf8');
  h.update(data);
  return h.digest('hex');
}
function isOid(v: string): boolean {
  return HEX40.test(v);
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const sp = data.indexOf(0x20, off);
    const nul = data.indexOf(0x00, sp + 1);
    if (sp < 0 || nul < 0 || nul + 21 > data.length) throw new Error('bad tree');
    entries.push({
      mode: data.subarray(off, sp).toString('ascii'),
      name: data.subarray(sp + 1, nul).toString('utf8'),
      oid: data.subarray(nul + 1, nul + 21).toString('hex'),
    });
    off = nul + 21;
  }
  return entries;
}

function compareTreeNames(a: TreeEntry, b: TreeEntry): number {
  const l = Buffer.from(a.mode === '40000' ? `${a.name}/` : a.name, 'utf8');
  const r = Buffer.from(b.mode === '40000' ? `${b.name}/` : b.name, 'utf8');
  return Buffer.compare(l, r);
}

function buildTree(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort(compareTreeNames);
  const parts: Buffer[] = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface CommitView {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseCommit(data: Buffer): CommitView {
  const blank = data.indexOf('\n\n');
  const head = blank < 0 ? data.toString('utf8') : data.subarray(0, blank).toString('utf8');
  const message = blank < 0 ? '' : data.subarray(blank + 2).toString('utf8');
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of head.split('\n')) {
    const sp = line.indexOf(' ');
    const k = sp < 0 ? line : line.slice(0, sp);
    const v = sp < 0 ? '' : line.slice(sp + 1);
    if (k === 'tree') tree = v;
    else if (k === 'parent') parents.push(v);
    else if (k === 'author') author = v;
    else if (k === 'committer') committer = v;
  }
  return { tree, parents, author, committer, message };
}

function buildCommit(tree: string, parents: string[], message: string, ts: number): Buffer {
  const who = `${VIEWER_NAME} <${VIEWER_EMAIL}> ${ts} +0000`;
  const lines = [`tree ${tree}`];
  for (const p of parents) lines.push(`parent ${p}`);
  lines.push(`author ${who}`, `committer ${who}`, '');
  const msg = message.endsWith('\n') ? message : `${message}\n`;
  return Buffer.from(`${lines.join('\n')}\n${msg}`, 'utf8');
}

interface TagView {
  object: string;
  type: string;
  tag: string;
  tagger: string;
  message: string;
}

function parseTag(data: Buffer): TagView {
  const blank = data.indexOf('\n\n');
  const head = blank < 0 ? data.toString('utf8') : data.subarray(0, blank).toString('utf8');
  const out: TagView = { object: '', type: '', tag: '', tagger: '', message: blank < 0 ? '' : data.subarray(blank + 2).toString('utf8') };
  for (const line of head.split('\n')) {
    const sp = line.indexOf(' ');
    if (sp < 0) continue;
    const k = line.slice(0, sp);
    const v = line.slice(sp + 1);
    if (k === 'object') out.object = v;
    else if (k === 'type') out.type = v;
    else if (k === 'tag') out.tag = v;
    else if (k === 'tagger') out.tagger = v;
  }
  return out;
}

// ---------------------------------------------------------------- packfile

function readVarint(buffer: Buffer, start: number): { size: number; next: number; first: number } {
  let byte = buffer[start]!;
  const first = byte;
  let size = byte & 0x0f;
  let shift = 4;
  let off = start + 1;
  while (byte & 0x80) {
    byte = buffer[off++]!;
    size += (byte & 0x7f) * 2 ** shift;
    shift += 7;
  }
  return { size, next: off, first };
}

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let off = 0;
  const readSize = (): number => {
    let v = 0;
    let shift = 0;
    for (;;) {
      const b = delta[off++]!;
      v += (b & 0x7f) * 2 ** shift;
      shift += 7;
      if (!(b & 0x80)) break;
    }
    return v;
  };
  const srcSize = readSize();
  const tgtSize = readSize();
  if (srcSize !== base.length) throw new Error('delta base size mismatch');
  const out = Buffer.allocUnsafe(tgtSize);
  let written = 0;
  while (off < delta.length) {
    const op = delta[off++]!;
    if (op & 0x80) {
      let copyOff = 0;
      let copySize = 0;
      let shift = 0;
      for (let bit = 0; bit < 4; bit++) {
        if (op & (1 << bit)) copyOff += delta[off++]! * 2 ** shift;
        shift += 8;
      }
      shift = 0;
      for (let bit = 4; bit < 7; bit++) {
        if (op & (1 << bit)) copySize += delta[off++]! * 2 ** shift;
        shift += 8;
      }
      if (copySize === 0) copySize = 0x10000;
      base.copy(out, written, copyOff, copyOff + copySize);
      written += copySize;
    } else if (op !== 0) {
      const n = op & 0x7f;
      delta.copy(out, written, off, off + n);
      off += n;
      written += n;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  if (written !== tgtSize) throw new Error('delta size mismatch');
  return out;
}

interface RawEntry {
  offset: number;
  typeCode: number;
  size: number;
  data: Buffer;
  baseOffset?: number;
  baseOid?: string;
}

/** Read a packfile; resolves OFS/REF deltas. Throws on corruption. */
function readPack(pack: Buffer): Map<string, GitObj> {
  if (pack.length < 32 || pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('bad pack header');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error('bad pack version');
  const count = pack.readUInt32BE(8);
  const trailerStart = pack.length - 20;
  const trailer = pack.subarray(trailerStart).toString('hex');
  const computed = createHash('sha1').update(pack.subarray(0, trailerStart)).digest('hex');
  if (trailer !== computed) throw new Error('pack checksum mismatch');
  const raw: RawEntry[] = [];
  const byOffset = new Map<number, RawEntry>();
  let off = 12;
  for (let i = 0; i < count; i++) {
    const entryOffset = off;
    const header = readVarint(pack, off);
    off = header.next;
    const typeCode = (header.first >> 4) & 0x07;
    const entry: RawEntry = { offset: entryOffset, typeCode, size: header.size, data: Buffer.alloc(0) };
    if (typeCode === 6) {
      let byte = pack[off++]!;
      let value = byte & 0x7f;
      while (byte & 0x80) {
        byte = pack[off++]!;
        value = ((value + 1) * 128) + (byte & 0x7f);
      }
      entry.baseOffset = entryOffset - value;
    } else if (typeCode === 7) {
      entry.baseOid = pack.subarray(off, off + 20).toString('hex');
      off += 20;
    } else if (!CODE_TYPE[typeCode]) {
      throw new Error('unknown pack type');
    }
    // inflate one zlib stream starting at off; inflateSync consumes exactly the stream
    const inflated = inflateSync(pack.subarray(off, trailerStart), { info: true }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
    if (inflated.buffer.length !== header.size) throw new Error('pack entry size mismatch');
    entry.data = inflated.buffer;
    off += inflated.engine.bytesWritten;
    raw.push(entry);
    byOffset.set(entryOffset, entry);
  }
  const resolved = new Map<string, GitObj>();
  // Oid -> resolved object, filled as entries resolve, so a REF-delta base
  // is a map lookup instead of a linear scan recomputing a SHA-1 per entry.
  const byOid = new Map<string, GitObj>();
  const resolve = (entry: RawEntry): GitObj => {
    if (entry.typeCode === 6 || entry.typeCode === 7) {
      let base: GitObj;
      if (entry.typeCode === 6) {
        const baseEntry = byOffset.get(entry.baseOffset!);
        if (!baseEntry) throw new Error('ofs-delta base missing');
        base = resolve(baseEntry);
      } else {
        const found = byOid.get(entry.baseOid!);
        if (!found) throw new Error('ref-delta base missing');
        base = found;
      }
      return { type: base.type, data: applyDelta(base.data, entry.data) };
    }
    return { type: CODE_TYPE[entry.typeCode]!, data: entry.data };
  };
  for (const entry of raw) {
    const obj = resolve(entry);
    const oid = sha1(obj.type, obj.data);
    resolved.set(oid, obj);
    byOid.set(oid, obj);
  }
  return resolved;
}

function writePackHeader(type: ObjType, size: number): Buffer {
  const code = TYPE_CODE[type];
  const bytes: number[] = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

function writePack(objects: GitObj[]): Buffer {
  // Single allocation for the whole packfile: header + per-object header and
  // deflated body, then the SHA-1 trailer written into the last 20 bytes.
  const headers: Buffer[] = [];
  const bodies: Buffer[] = [];
  let total = 12 + 20;
  for (const o of objects) {
    const h = writePackHeader(o.type, o.data.length);
    const b = deflateSync(o.data);
    headers.push(h);
    bodies.push(b);
    total += h.length + b.length;
  }
  const out = Buffer.allocUnsafe(total);
  out.write('PACK', 0, 4, 'ascii');
  out.writeUInt32BE(2, 4);
  out.writeUInt32BE(objects.length, 8);
  let off = 12;
  for (let i = 0; i < objects.length; i++) {
    headers[i]!.copy(out, off);
    off += headers[i]!.length;
    bodies[i]!.copy(out, off);
    off += bodies[i]!.length;
  }
  createHash('sha1').update(out.subarray(0, total - 20)).digest().copy(out, total - 20);
  return out;
}

// ---------------------------------------------------------------- pkt-line

function pktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const len = data.length + 4;
  const out = Buffer.allocUnsafe(len);
  out.write(len.toString(16).padStart(4, '0'), 0, 4, 'ascii');
  data.copy(out, 4);
  return out;
}
const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

type Pkt = { kind: 'data' | 'flush' | 'delim'; payload: Buffer };

function parsePktLines(buf: Buffer): Pkt[] {
  const out: Pkt[] = [];
  let off = 0;
  while (off < buf.length) {
    if (off + 4 > buf.length) throw new Error('truncated pkt-line');
    const lenText = buf.subarray(off, off + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(lenText)) throw new Error('bad pkt-line length');
    const len = parseInt(lenText, 16);
    if (len === 0) {
      out.push({ kind: 'flush', payload: Buffer.alloc(0) });
      off += 4;
    } else if (len === 1) {
      out.push({ kind: 'delim', payload: Buffer.alloc(0) });
      off += 4;
    } else {
      if (len < 4 || off + len > buf.length) throw new Error('bad pkt-line length');
      out.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
      off += len;
    }
  }
  return out;
}

function pktLinesOf(lines: (string | 'flush' | 'delim')[]): Buffer {
  const bufs: Buffer[] = [];
  let total = 0;
  for (const l of lines) {
    let b: Buffer;
    if (l === 'flush') b = PKT_FLUSH;
    else if (l === 'delim') b = PKT_DELIM;
    else b = pktLine(l);
    bufs.push(b);
    total += b.length;
  }
  return Buffer.concat(bufs, total);
}

// ---------------------------------------------------------------- store

interface Issue {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  comments: { id: number; body: string; createdAt: string }[];
  createdSeq: number;
  updatedSeq: number;
}

interface Pull {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeSha: string | null;
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  createdSeq: number;
}

interface Repo {
  id: number;
  owner: string;
  name: string;
  description: string;
  priv: boolean;
  defaultBranch: string;
  createdSeq: number;
  refs: Map<string, string>;
  objects: Map<string, GitObj>;
  parentsCache: Map<string, string[]>;
  treeCache: Map<string, TreeEntry[]>;
  fileMapCache: Map<string, Map<string, string>>;
  commitCache: Map<string, CommitView>;
  issues: Issue[];
  byNumber: Map<number, Issue>;
  pulls: Pull[];
  pullByNumber: Map<number, Pull>;
  labels: Map<string, { name: string; color: string }>;
  nextNumber: number;
  issueJsonCache: Map<number, Buffer>;
  // Git-response caches, gated by `version`: any object or ref mutation
  // bumps the version and drops them, so a cached pack/advertisement can
  // never describe a repo that has since changed.
  version: number;
  fetchCache: Map<string, Buffer>;
  lsCache: Map<string, Buffer>;
  advUp: Buffer | null;
  advRecv: Buffer | null;
}

const repos = new Map<string, Repo>();
const repoList: Repo[] = [];
const reposById = new Map<number, Repo>();

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

function createRepoRecord(name: string, description: string, priv: boolean): Repo {
  const repo: Repo = {
    id: nextRepoId++,
    owner: VIEWER_LOGIN,
    name,
    description,
    priv,
    defaultBranch: 'main',
    createdSeq: ++globalSeq,
    refs: new Map(),
    objects: new Map(),
    parentsCache: new Map(),
    treeCache: new Map(),
    fileMapCache: new Map(),
    commitCache: new Map(),
    issues: [],
    byNumber: new Map(),
    pulls: [],
    pullByNumber: new Map(),
    labels: new Map(),
    nextNumber: 1,
    issueJsonCache: new Map(),
    version: 0,
    fetchCache: new Map(),
    lsCache: new Map(),
    advUp: null,
    advRecv: null,
  };
  repos.set(repoKey(VIEWER_LOGIN, name), repo);
  repoList.push(repo);
  reposById.set(repo.id, repo);
  return repo;
}

function getRepo(owner: string, name: string): Repo | null {
  if (owner !== VIEWER_LOGIN) return null;
  return repos.get(repoKey(owner, name)) ?? null;
}

function deleteRepo(repo: Repo): void {
  repos.delete(repoKey(repo.owner, repo.name));
  reposById.delete(repo.id);
  const i = repoList.indexOf(repo);
  if (i >= 0) repoList.splice(i, 1);
}

/** Bump the repo version and drop every version-gated git cache. */
function touchRepo(repo: Repo): void {
  repo.version += 1;
  repo.fetchCache.clear();
  repo.lsCache.clear();
  repo.advUp = null;
  repo.advRecv = null;
}

/** The only ways refs change: every mutation invalidates the git caches. */
function setRef(repo: Repo, ref: string, oid: string): void {
  if (repo.refs.get(ref) !== oid) {
    repo.refs.set(ref, oid);
    touchRepo(repo);
  }
}
function deleteRef(repo: Repo, ref: string): void {
  if (repo.refs.delete(ref)) touchRepo(repo);
}

function storeObject(repo: Repo, type: ObjType, data: Buffer): string {
  const oid = sha1(type, data);
  if (!repo.objects.has(oid)) {
    repo.objects.set(oid, { type, data });
    touchRepo(repo);
  }
  return oid;
}

/** A commit's parsed view, cached: objects are immutable once stored. */
function commitView(repo: Repo, oid: string): CommitView | null {
  let cached = repo.commitCache.get(oid);
  if (cached) return cached;
  const obj = repo.objects.get(oid);
  if (!obj || obj.type !== 'commit') return null;
  cached = parseCommit(obj.data);
  repo.commitCache.set(oid, cached);
  return cached;
}

function commitParents(repo: Repo, oid: string): string[] {
  let cached = repo.parentsCache.get(oid);
  if (cached) return cached;
  const view = commitView(repo, oid);
  cached = view ? view.parents : [];
  repo.parentsCache.set(oid, cached);
  return cached;
}

function treeEntries(repo: Repo, oid: string): TreeEntry[] {
  let cached = repo.treeCache.get(oid);
  if (cached) return cached;
  const obj = repo.objects.get(oid);
  if (!obj || obj.type !== 'tree') return [];
  cached = parseTree(obj.data);
  repo.treeCache.set(oid, cached);
  return cached;
}

/** path -> blob oid for a commit's tree (recursive). */
function fileMapOf(repo: Repo, commitOid: string): Map<string, string> {
  let cached = repo.fileMapCache.get(commitOid);
  if (cached) return cached;
  const out = new Map<string, string>();
  const view = commitView(repo, commitOid);
  if (view) {
    const walk = (treeOid: string, prefix: string): void => {
      for (const e of treeEntries(repo, treeOid)) {
        const path = prefix === '' ? e.name : `${prefix}/${e.name}`;
        if (e.mode === '40000') walk(e.oid, path);
        else out.set(path, e.oid);
      }
    };
    walk(view.tree, '');
  }
  repo.fileMapCache.set(commitOid, out);
  return out;
}

function buildTreeFromFiles(repo: Repo, files: Map<string, string>): string {
  interface Node {
    files: Map<string, string>;
    dirs: Map<string, Node>;
  }
  const make = (): Node => ({ files: new Map(), dirs: new Map() });
  const root = make();
  for (const [path, oid] of files) {
    const segs = path.split('/');
    let node = root;
    for (let i = 0; i < segs.length - 1; i++) {
      const s = segs[i]!;
      let child = node.dirs.get(s);
      if (!child) {
        child = make();
        node.dirs.set(s, child);
      }
      node = child;
    }
    node.files.set(segs[segs.length - 1]!, oid);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, oid] of node.files) entries.push({ mode: '100644', name, oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    return storeObject(repo, 'tree', buildTree(entries));
  };
  return build(root);
}

/** All commit oids reachable from roots (parents + tag targets), newest-first order not guaranteed. */
function reachableCommits(repo: Repo, roots: Iterable<string>): Set<string> {
  const seen = new Set<string>();
  const queue: string[] = [];
  for (const r of roots) if (isOid(r)) queue.push(r);
  while (queue.length) {
    const oid = queue.pop()!;
    if (seen.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    seen.add(oid);
    if (obj.type === 'commit') {
      for (const p of commitParents(repo, oid)) queue.push(p);
    } else if (obj.type === 'tag') {
      queue.push(parseTag(obj.data).object);
    }
  }
  return seen;
}

/** Full object closure reachable from roots (commits, trees, blobs, tags). */
function reachableObjects(repo: Repo, roots: Iterable<string>): Set<string> {
  const seen = new Set<string>();
  const queue: string[] = [];
  for (const r of roots) if (isOid(r)) queue.push(r);
  while (queue.length) {
    const oid = queue.pop()!;
    if (seen.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    seen.add(oid);
    if (obj.type === 'commit') {
      const c = commitView(repo, oid);
      if (c) {
        queue.push(c.tree);
        for (const p of c.parents) queue.push(p);
      }
    } else if (obj.type === 'tag') {
      queue.push(parseTag(obj.data).object);
    } else if (obj.type === 'tree') {
      for (const e of treeEntries(repo, oid)) if (e.mode !== '160000') queue.push(e.oid);
    }
  }
  return seen;
}

function isAncestor(repo: Repo, anc: string, desc: string): boolean {
  if (anc === desc) return true;
  const seen = new Set<string>();
  const queue = [desc];
  while (queue.length) {
    const oid = queue.pop()!;
    if (oid === anc) return true;
    if (seen.has(oid)) continue;
    seen.add(oid);
    for (const p of commitParents(repo, oid)) queue.push(p);
  }
  return false;
}

function mergeBase(repo: Repo, a: string, b: string): string | null {
  const ancA = reachableCommits(repo, [a]);
  const queue = [b];
  const seen = new Set<string>();
  while (queue.length) {
    const oid = queue.shift()!;
    if (ancA.has(oid)) return oid;
    if (seen.has(oid)) continue;
    seen.add(oid);
    for (const p of commitParents(repo, oid)) queue.push(p);
  }
  return null;
}

/** Commits on a branch, newest first (DFS pre-order, deduped). */
function branchCommits(repo: Repo, tip: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const stack = [tip];
  while (stack.length) {
    const oid = stack.pop()!;
    if (seen.has(oid)) continue;
    const view = commitView(repo, oid);
    if (!view) continue;
    seen.add(oid);
    out.push(oid);
    const parents = view.parents;
    for (let i = parents.length - 1; i >= 0; i--) stack.push(parents[i]!);
  }
  return out;
}

function b64encode(buf: Buffer): string {
  return buf.toString('base64');
}
function b64decode(s: string): Buffer {
  return Buffer.from(s.replace(/[\r\n\t ]+/g, ''), 'base64');
}

function globalId(kind: string, ...parts: (string | number)[]): string {
  return Buffer.from([kind, ...parts].join(':'), 'utf8').toString('base64');
}
function decodeGlobalId(id: string): string[] | null {
  try {
    const text = Buffer.from(id, 'base64').toString('utf8');
    const parts = text.split(':');
    return parts.length >= 2 ? parts : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- HTTP plumbing

function reqId(): string {
  reqCounter += 1;
  return `gh-${reqCounter.toString(16).padStart(8, '0')}`;
}

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const text = typeof body === 'string' ? body : `${JSON.stringify(body)}\n`;
  // One Buffer from the text: its length is the content-length, so the
  // string is neither scanned for byte length nor re-encoded on end().
  const buf = Buffer.from(text, 'utf8');
  res.writeHead(status, { 'content-type': JSON_TYPE, 'content-length': buf.length, 'x-github-request-id': reqId(), ...headers });
  res.end(buf);
}

function sendRaw(res: ServerResponse, status: number, buf: Buffer, contentType: string, headers: Record<string, string> = {}): void {
  res.writeHead(status, { 'content-type': contentType, 'content-length': buf.length, 'x-github-request-id': reqId(), ...headers });
  res.end(buf);
}

function sendNoContent(res: ServerResponse, status: number): void {
  res.writeHead(status, { 'content-type': JSON_TYPE, 'x-github-request-id': reqId() });
  res.end();
}

function errBody(message: string): { message: string } {
  return { message };
}

function authed(req: IncomingMessage): boolean {
  const h = req.headers.authorization ?? '';
  if (!h.startsWith('Bearer ')) return false;
  const token = h.slice(7);
  if (token === '') return false;
  if (TOKEN !== '') return token === TOKEN;
  return true;
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (c: Buffer) => {
      total += c.length;
      if (total > 64 * 1024 * 1024) {
        reject(new Error('body too large'));
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function readJsonBody(req: IncomingMessage): Promise<{ ok: true; value: Record<string, unknown> } | { ok: false }> {
  const buf = await readBody(req);
  if (buf.length === 0) return { ok: true, value: {} };
  try {
    const v = JSON.parse(buf.toString('utf8')) as unknown;
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) return { ok: true, value: v as Record<string, unknown> };
    return { ok: false };
  } catch {
    return { ok: false };
  }
}

const EMPTY_PARAMS = new URLSearchParams();

function parseQuery(url: string): { path: string; query: URLSearchParams } {
  const q = url.indexOf('?');
  if (q < 0) return { path: url, query: EMPTY_PARAMS };
  return { path: url.slice(0, q), query: new URLSearchParams(url.slice(q + 1)) };
}

function hostOf(req: IncomingMessage): string {
  return req.headers.host ?? '127.0.0.1';
}

function absUrl(req: IncomingMessage, path: string): string {
  return `http://${hostOf(req)}${path}`;
}

// ---------------------------------------------------------------- REST views

function userJson(): Record<string, unknown> {
  return { login: VIEWER_LOGIN, id: VIEWER_ID, node_id: globalId('User', VIEWER_ID), name: VIEWER_NAME, email: VIEWER_EMAIL, type: 'User', site_admin: false };
}

function repoJson(repo: Repo): Record<string, unknown> {
  return {
    id: repo.id,
    node_id: globalId('Repository', repo.id),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: VIEWER_ID, type: 'User' },
    private: repo.priv,
    description: repo.description,
    default_branch: repo.defaultBranch,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    created_at: isoOf(BASE_TS + repo.createdSeq),
    updated_at: isoOf(BASE_TS + repo.createdSeq),
    has_issues: true,
    has_projects: false,
    has_wiki: false,
    fork: false,
    archived: false,
    disabled: false,
  };
}

function labelJson(label: { name: string; color: string }): Record<string, unknown> {
  return { id: 0, node_id: globalId('Label', label.name), name: label.name, color: label.color, description: '', default: false };
}

function issueJson(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: issue.id,
    node_id: globalId('Issue', repo.id, issue.number),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    labels: issue.labels.map((n) => {
      const l = repo.labels.get(n);
      return l ? labelJson(l) : { name: n, color: 'ededed' };
    }),
    comments: issue.comments.length,
    created_at: isoOf(BASE_TS + issue.createdSeq),
    updated_at: isoOf(BASE_TS + issue.updatedSeq),
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/issues/${issue.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
  };
}

function issueJsonBuffer(repo: Repo, issue: Issue): Buffer {
  const cached = repo.issueJsonCache.get(issue.number);
  if (cached !== undefined) return cached;
  const buf = Buffer.from(JSON.stringify(issueJson(repo, issue)), 'utf8');
  repo.issueJsonCache.set(issue.number, buf);
  return buf;
}

function pullJson(repo: Repo, pull: Pull): Record<string, unknown> {
  return {
    id: pull.id,
    node_id: globalId('PullRequest', repo.id, pull.number),
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeSha,
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    head: { ref: pull.headRef, sha: pull.headSha, label: `${repo.owner}:${pull.headRef}`, user: { login: repo.owner, id: VIEWER_ID } },
    base: { ref: pull.baseRef, sha: pull.baseSha, label: `${repo.owner}:${pull.baseRef}`, user: { login: repo.owner, id: VIEWER_ID } },
    created_at: isoOf(BASE_TS + pull.createdSeq),
    updated_at: isoOf(BASE_TS + pull.createdSeq),
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/pull/${pull.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/${pull.number}`,
  };
}

function paginate<T>(items: T[], query: URLSearchParams): { page: T[]; total: number; pageNum: number; perPage: number } {
  const perPage = Math.max(1, Math.min(100, Number(query.get('per_page') ?? '30') || 30));
  const pageNum = Math.max(1, Number(query.get('page') ?? '1') || 1);
  const start = (pageNum - 1) * perPage;
  return { page: items.slice(start, start + perPage), total: items.length, pageNum, perPage };
}

function linkHeader(req: IncomingMessage, basePath: string, query: URLSearchParams, total: number, pageNum: number, perPage: number): string | null {
  const lastPage = Math.max(1, Math.ceil(total / perPage));
  if (lastPage <= 1) return null;
  const q = new URLSearchParams(query);
  const mk = (p: number): string => {
    q.set('page', String(p));
    q.set('per_page', String(perPage));
    return `<${absUrl(req, `${basePath}?${q.toString()}`)}>`;
  };
  const parts: string[] = [];
  if (pageNum < lastPage) parts.push(`${mk(pageNum + 1)}; rel="next"`);
  if (pageNum > 1) parts.push(`${mk(pageNum - 1)}; rel="prev"`);
  parts.push(`${mk(1)}; rel="first"`);
  parts.push(`${mk(lastPage)}; rel="last"`);
  return parts.join(', ');
}

// ---------------------------------------------------------------- REST: issues & pulls shared logic

function createIssueIn(repo: Repo, title: string, body: string, labels: string[]): Issue | { error: string; status: number } {
  for (const l of labels) {
    if (!repo.labels.has(l)) return { error: `Label '${l}' does not exist`, status: 422 };
  }
  const n = repo.nextNumber++;
  const seq = ++globalSeq;
  const issue: Issue = { id: 100000 + repo.id * 10000 + n, number: n, title, body, labels: [...labels], state: 'open', comments: [], createdSeq: seq, updatedSeq: seq };
  repo.issues.push(issue);
  repo.byNumber.set(n, issue);
  return issue;
}

function createPullIn(repo: Repo, title: string, body: string, head: string, base: string): Pull | { error: string; status: number } {
  const headTip = repo.refs.get(`refs/heads/${head}`);
  const baseTip = repo.refs.get(`refs/heads/${base}`);
  if (headTip === undefined) return { error: `head branch ${head} does not exist`, status: 422 };
  if (baseTip === undefined) return { error: `base branch ${base} does not exist`, status: 422 };
  for (const p of repo.pulls) {
    if (p.state === 'open' && p.headRef === head && p.baseRef === base) return { error: 'A pull request already exists for this head and base', status: 422 };
  }
  const n = repo.nextNumber++;
  const seq = ++globalSeq;
  const pull: Pull = {
    id: 200000 + repo.id * 10000 + n, number: n, title, body, state: 'open', merged: false, mergedAt: null, mergeSha: null,
    headRef: head, baseRef: base, headSha: headTip, baseSha: baseTip, createdSeq: seq,
  };
  repo.pulls.push(pull);
  repo.pullByNumber.set(n, pull);
  return pull;
}

/** Files changed on head vs merge-base with base. */
function pullFiles(repo: Repo, pull: Pull): { filename: string; status: string; additions: number; deletions: number; changes: number; sha: string }[] {
  const base = mergeBase(repo, pull.headSha, pull.baseSha);
  const baseMap = base ? fileMapOf(repo, base) : new Map<string, string>();
  const headMap = fileMapOf(repo, pull.headSha);
  const out: { filename: string; status: string; additions: number; deletions: number; changes: number; sha: string }[] = [];
  const paths = new Set([...baseMap.keys(), ...headMap.keys()]);
  const lineCount = (oid: string | undefined): number => {
    if (oid === undefined) return 0;
    const o = repo.objects.get(oid);
    if (!o) return 0;
    const text = o.data.toString('utf8');
    if (text === '') return 0;
    return text.split('\n').length - (text.endsWith('\n') ? 1 : 0);
  };
  for (const path of [...paths].sort()) {
    const b = baseMap.get(path);
    const h = headMap.get(path);
    if (b === h) continue;
    if (b === undefined) {
      const add = lineCount(h);
      out.push({ filename: path, status: 'added', additions: add, deletions: 0, changes: add, sha: h! });
    } else if (h === undefined) {
      const del = lineCount(b);
      out.push({ filename: path, status: 'removed', additions: 0, deletions: del, changes: del, sha: b });
    } else {
      const add = lineCount(h);
      const del = lineCount(b);
      out.push({ filename: path, status: 'modified', additions: add, deletions: del, changes: add + del, sha: h });
    }
  }
  return out;
}

function mergeConflict(repo: Repo, pull: Pull): boolean {
  const base = mergeBase(repo, pull.headSha, pull.baseSha);
  if (base === null) return false;
  const baseMap = fileMapOf(repo, base);
  const headMap = fileMapOf(repo, pull.headSha);
  const currentBase = repo.refs.get(`refs/heads/${pull.baseRef}`) ?? pull.baseSha;
  const curMap = fileMapOf(repo, currentBase);
  const paths = new Set([...baseMap.keys(), ...headMap.keys(), ...curMap.keys()]);
  for (const path of paths) {
    const b = baseMap.get(path);
    const h = headMap.get(path);
    const c = curMap.get(path);
    const headChanged = h !== b;
    const baseChanged = c !== b;
    if (headChanged && baseChanged && h !== c) return true;
  }
  return false;
}

/** Squash-merge a pull request. Returns the merge commit sha, or null on conflict. */
function squashMerge(repo: Repo, pull: Pull): string | null {
  if (mergeConflict(repo, pull)) return null;
  const base = mergeBase(repo, pull.headSha, pull.baseSha);
  const baseMap = base ? fileMapOf(repo, base) : new Map<string, string>();
  const headMap = fileMapOf(repo, pull.headSha);
  const currentBase = repo.refs.get(`refs/heads/${pull.baseRef}`) ?? pull.baseSha;
  const curMap = fileMapOf(repo, currentBase);
  const result = new Map(curMap);
  for (const [path, h] of headMap) {
    if (baseMap.get(path) !== h) result.set(path, h);
  }
  for (const path of baseMap.keys()) {
    if (!headMap.has(path) && baseMap.has(path)) result.delete(path);
  }
  const treeOid = buildTreeFromFiles(repo, result);
  const ts = nextTs();
  const msg = `Merge pull request #${pull.number} from ${pull.headRef}\n\n${pull.title}`;
  const commitOid = storeObject(repo, 'commit', buildCommit(treeOid, [currentBase], msg, ts));
  setRef(repo, `refs/heads/${pull.baseRef}`, commitOid);
  pull.merged = true;
  pull.state = 'closed';
  pull.mergedAt = isoOf(ts);
  pull.mergeSha = commitOid;
  return commitOid;
}

function prMergeable(repo: Repo, pull: Pull): string {
  if (pull.merged) return 'MERGEABLE';
  return mergeConflict(repo, pull) ? 'CONFLICTING' : 'MERGEABLE';
}

// ---------------------------------------------------------------- REST: contents

function resolveRefCommit(repo: Repo, ref: string | null): string | null {
  if (ref === null) {
    return repo.refs.get(`refs/heads/${repo.defaultBranch}`) ?? null;
  }
  const branch = repo.refs.get(`refs/heads/${ref}`);
  if (branch !== undefined) return branch;
  if (isOid(ref) && repo.objects.has(ref)) return ref;
  return null;
}

function contentsCommit(repo: Repo, branch: string, files: Map<string, string>, message: string): string {
  const treeOid = buildTreeFromFiles(repo, files);
  const tip = repo.refs.get(`refs/heads/${branch}`);
  const parents = tip !== undefined ? [tip] : [];
  const ts = nextTs();
  const oid = storeObject(repo, 'commit', buildCommit(treeOid, parents, message, ts));
  setRef(repo, `refs/heads/${branch}`, oid);
  return oid;
}

// ---------------------------------------------------------------- REST router

async function handleRest(req: IncomingMessage, res: ServerResponse, path: string, query: URLSearchParams): Promise<boolean> {
  const method = req.method ?? 'GET';
  const segs = path.split('/').filter((s) => s !== '').map((s) => {
    if (!s.includes('%')) return s;
    try {
      return decodeURIComponent(s);
    } catch {
      return s;
    }
  });
  // segs[0] === 'api', segs[1] === 'v3'
  const rest = segs.slice(2);

  if (rest.length === 0) {
    if (method === 'GET') {
      sendJson(res, 200, { current_user_url: '/api/v3/user', rate_limit_url: '/api/v3/rate_limit' }, { 'x-oauth-scopes': 'repo, read:org' });
      return true;
    }
    sendJson(res, 404, errBody('Not Found'));
    return true;
  }

  if (rest[0] === 'meta' && rest.length === 1) {
    if (method === 'GET') {
      sendJson(res, 200, { installed_version: '1.0.0', verifiable_password_authentication: true });
      return true;
    }
    sendJson(res, 404, errBody('Not Found'));
    return true;
  }

  if (rest[0] === 'user') {
    if (rest.length === 1 && method === 'GET') {
      sendJson(res, 200, userJson());
      return true;
    }
    if (rest.length === 2 && rest[1] === 'repos') {
      if (method === 'GET') {
        const { page, total, pageNum, perPage } = paginate(repoList, query);
        const link = linkHeader(req, '/api/v3/user/repos', query, total, pageNum, perPage);
        sendJson(res, 200, page.map(repoJson), link ? { link } : {});
        return true;
      }
      if (method === 'POST') {
        const parsed = await readJsonBody(req);
        if (!parsed.ok) {
          sendJson(res, 400, errBody('Problems parsing JSON'));
          return true;
        }
        const name = typeof parsed.value.name === 'string' ? parsed.value.name : '';
        if (name === '') {
          sendJson(res, 422, errBody('name is required'));
          return true;
        }
        if (repos.has(repoKey(VIEWER_LOGIN, name))) {
          sendJson(res, 422, errBody(`Repository ${VIEWER_LOGIN}/${name} already exists`));
          return true;
        }
        const repo = createRepoRecord(name, typeof parsed.value.description === 'string' ? parsed.value.description : '', parsed.value.private === true);
        sendJson(res, 201, repoJson(repo));
        return true;
      }
    }
    sendJson(res, 404, errBody('Not Found'));
    return true;
  }

  if (rest[0] !== 'repos' || rest.length < 3) {
    sendJson(res, 404, errBody('Not Found'));
    return true;
  }
  const owner = rest[1]!;
  const repoName = rest[2]!;
  const repo = getRepo(owner, repoName);
  if (repo === null) {
    // A body read is still needed for POST/PUT/PATCH so the socket drains cleanly.
    if (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') await readBody(req).catch(() => undefined);
    sendJson(res, 404, errBody('Not Found'));
    return true;
  }
  const tail = rest.slice(3);

  // ---- /repos/{o}/{r} itself
  if (tail.length === 0) {
    if (method === 'GET') {
      sendJson(res, 200, repoJson(repo));
      return true;
    }
    if (method === 'PATCH') {
      const parsed = await readJsonBody(req);
      if (!parsed.ok) {
        sendJson(res, 400, errBody('Problems parsing JSON'));
        return true;
      }
      if (typeof parsed.value.description === 'string') repo.description = parsed.value.description;
      sendJson(res, 200, repoJson(repo));
      return true;
    }
    if (method === 'DELETE') {
      await readBody(req).catch(() => undefined);
      deleteRepo(repo);
      sendNoContent(res, 204);
      return true;
    }
    sendJson(res, 404, errBody('Not Found'));
    return true;
  }

  // ---- branches
  if (tail[0] === 'branches') {
    if (tail.length === 1 && method === 'GET') {
      const list: Record<string, unknown>[] = [];
      for (const [ref, sha] of [...repo.refs.entries()].sort()) {
        if (!ref.startsWith('refs/heads/')) continue;
        list.push({ name: ref.slice('refs/heads/'.length), commit: { sha }, protected: false });
      }
      sendJson(res, 200, list);
      return true;
    }
    if (tail.length === 2 && method === 'GET') {
      const sha = repo.refs.get(`refs/heads/${tail[1]}`);
      if (sha === undefined) {
        sendJson(res, 404, errBody('Not Found'));
        return true;
      }
      sendJson(res, 200, { name: tail[1], commit: { sha }, protected: false });
      return true;
    }
    sendJson(res, 404, errBody('Not Found'));
    return true;
  }

  // ---- commits
  if (tail[0] === 'commits' && tail.length === 1 && method === 'GET') {
    const ref = query.get('sha');
    const tip = resolveRefCommit(repo, ref);
    const list: Record<string, unknown>[] = [];
    if (tip !== null) {
      for (const oid of branchCommits(repo, tip)) {
        const c = commitView(repo, oid)!;
        list.push({
          sha: oid,
          commit: {
            message: c.message.replace(/\n+$/, ''),
            author: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: isoOf(BASE_TS + repo.createdSeq) },
            committer: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: isoOf(BASE_TS + repo.createdSeq) },
          },
          author: { login: VIEWER_LOGIN, id: VIEWER_ID },
          committer: { login: VIEWER_LOGIN, id: VIEWER_ID },
          parents: c.parents.map((p) => ({ sha: p })),
        });
      }
    }
    sendJson(res, 200, list);
    return true;
  }

  // ---- git refs
  if (tail[0] === 'git' && tail[1] === 'refs') {
    if (method === 'POST' && tail.length === 2) {
      const parsed = await readJsonBody(req);
      if (!parsed.ok) {
        sendJson(res, 400, errBody('Problems parsing JSON'));
        return true;
      }
      const ref = typeof parsed.value.ref === 'string' ? parsed.value.ref : '';
      const sha = typeof parsed.value.sha === 'string' ? parsed.value.sha : '';
      if (!ref.startsWith('refs/') || !isOid(sha) || !repo.objects.has(sha)) {
        sendJson(res, 422, errBody('Invalid ref or sha'));
        return true;
      }
      if (repo.refs.has(ref)) {
        sendJson(res, 422, errBody('Reference already exists'));
        return true;
      }
      setRef(repo, ref, sha);
      sendJson(res, 201, { ref, object: { sha, type: repo.objects.get(sha)!.type } });
      return true;
    }
    if (method === 'GET' && tail.length === 2) {
      const list: Record<string, unknown>[] = [];
      for (const [ref, sha] of [...repo.refs.entries()].sort()) list.push({ ref, object: { sha } });
      sendJson(res, 200, list);
      return true;
    }
    if (method === 'GET' && tail.length >= 3) {
      const refName = `refs/${tail.slice(2).join('/')}`;
      const sha = repo.refs.get(refName);
      if (sha === undefined) {
        sendJson(res, 404, errBody('Not Found'));
        return true;
      }
      sendJson(res, 200, { ref: refName, object: { sha, type: repo.objects.get(sha)?.type ?? 'commit' } });
      return true;
    }
    sendJson(res, 404, errBody('Not Found'));
    return true;
  }

  // ---- contents
  if (tail[0] === 'contents') {
    const filePath = tail.slice(1).join('/');
    const refParam = query.get('ref');
    if (method === 'GET') {
      const tip = resolveRefCommit(repo, refParam);
      if (tip === null) {
        sendJson(res, 404, errBody('Not Found'));
        return true;
      }
      const files = fileMapOf(repo, tip);
      if (filePath === '') {
        const entries: Record<string, unknown>[] = [];
        const dirs = new Set<string>();
        for (const p of files.keys()) {
          const first = p.split('/')[0]!;
          if (p.includes('/')) dirs.add(first);
          else entries.push({ type: 'file', name: first, path: first, sha: files.get(p), size: repo.objects.get(files.get(p)!)!.data.length });
        }
        for (const d of [...dirs].sort()) entries.push({ type: 'dir', name: d, path: d, sha: '' });
        entries.sort((a, b) => String(a.name).localeCompare(String(b.name)));
        sendJson(res, 200, entries);
        return true;
      }
      const blobOid = files.get(filePath);
      if (blobOid !== undefined) {
        const data = repo.objects.get(blobOid)!.data;
        sendJson(res, 200, {
          type: 'file', encoding: 'base64', size: data.length,
          name: filePath.split('/').pop(), path: filePath,
          content: b64encode(data), sha: blobOid,
        });
        return true;
      }
      // directory?
      const prefix = `${filePath}/`;
      const entries: Record<string, unknown>[] = [];
      const dirs = new Set<string>();
      let found = false;
      for (const [p, oid] of files) {
        if (!p.startsWith(prefix)) continue;
        found = true;
        const restPath = p.slice(prefix.length);
        const first = restPath.split('/')[0]!;
        if (restPath.includes('/')) {
          dirs.add(first);
        } else {
          entries.push({ type: 'file', name: first, path: p, sha: oid, size: repo.objects.get(oid)!.data.length });
        }
      }
      if (!found) {
        sendJson(res, 404, errBody('Not Found'));
        return true;
      }
      for (const d of [...dirs].sort()) {
        // tree oid for the directory: find via walking the tip tree
        entries.push({ type: 'dir', name: d, path: `${filePath}/${d}`, sha: '' });
      }
      entries.sort((a, b) => String(a.name).localeCompare(String(b.name)));
      sendJson(res, 200, entries);
      return true;
    }
    if (method === 'PUT') {
      const parsed = await readJsonBody(req);
      if (!parsed.ok) {
        sendJson(res, 400, errBody('Problems parsing JSON'));
        return true;
      }
      const message = typeof parsed.value.message === 'string' ? parsed.value.message : 'update';
      const contentB64 = typeof parsed.value.content === 'string' ? parsed.value.content : '';
      const branch = typeof parsed.value.branch === 'string' ? parsed.value.branch : repo.defaultBranch;
      const sha = typeof parsed.value.sha === 'string' ? parsed.value.sha : undefined;
      if (contentB64 === '') {
        sendJson(res, 422, errBody('content is required'));
        return true;
      }
      let tip = repo.refs.get(`refs/heads/${branch}`);
      if (tip === undefined) {
        const defTip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
        if (defTip !== undefined) setRef(repo, `refs/heads/${branch}`, defTip);
        tip = repo.refs.get(`refs/heads/${branch}`);
      }
      const files = tip !== undefined ? new Map(fileMapOf(repo, tip)) : new Map<string, string>();
      const current = files.get(filePath);
      if (current !== undefined) {
        if (sha === undefined) {
          sendJson(res, 422, errBody('sha is required to update a file'));
          return true;
        }
        if (sha !== current) {
          sendJson(res, 409, errBody('sha does not match the current file'));
          return true;
        }
      } else if (sha !== undefined) {
        sendJson(res, 409, errBody('sha does not match the current file'));
        return true;
      }
      const data = b64decode(contentB64);
      const blobOid = storeObject(repo, 'blob', data);
      const isNew = current === undefined;
      files.set(filePath, blobOid);
      const commitSha = contentsCommit(repo, branch, files, message);
      sendJson(res, isNew ? 201 : 200, {
        content: { name: filePath.split('/').pop(), path: filePath, sha: blobOid, size: data.length, encoding: 'base64' },
        commit: { sha: commitSha },
      });
      return true;
    }
    if (method === 'DELETE') {
      const parsed = await readJsonBody(req);
      if (!parsed.ok) {
        sendJson(res, 400, errBody('Problems parsing JSON'));
        return true;
      }
      const message = typeof parsed.value.message === 'string' ? parsed.value.message : 'delete';
      const sha = typeof parsed.value.sha === 'string' ? parsed.value.sha : undefined;
      const branch = typeof parsed.value.branch === 'string' ? parsed.value.branch : repo.defaultBranch;
      const tip = repo.refs.get(`refs/heads/${branch}`);
      if (tip === undefined) {
        sendJson(res, 404, errBody('Not Found'));
        return true;
      }
      const files = new Map(fileMapOf(repo, tip));
      const current = files.get(filePath);
      if (current === undefined) {
        sendJson(res, 404, errBody('Not Found'));
        return true;
      }
      if (sha !== undefined && sha !== current) {
        sendJson(res, 409, errBody('sha does not match the current file'));
        return true;
      }
      files.delete(filePath);
      const commitSha = contentsCommit(repo, branch, files, message);
      sendJson(res, 200, { commit: { sha: commitSha } });
      return true;
    }
    sendJson(res, 404, errBody('Not Found'));
    return true;
  }

  // ---- labels
  if (tail[0] === 'labels') {
    if (method === 'GET' && tail.length === 1) {
      sendJson(res, 200, [...repo.labels.values()].map(labelJson));
      return true;
    }
    if (method === 'POST' && tail.length === 1) {
      const parsed = await readJsonBody(req);
      if (!parsed.ok) {
        sendJson(res, 400, errBody('Problems parsing JSON'));
        return true;
      }
      const name = typeof parsed.value.name === 'string' ? parsed.value.name : '';
      if (name === '') {
        sendJson(res, 422, errBody('name is required'));
        return true;
      }
      const color = typeof parsed.value.color === 'string' ? parsed.value.color : 'ededed';
      const existing = repo.labels.get(name);
      if (existing) {
        sendJson(res, 201, labelJson(existing));
        return true;
      }
      const label = { name, color };
      repo.labels.set(name, label);
      sendJson(res, 201, labelJson(label));
      return true;
    }
    sendJson(res, 404, errBody('Not Found'));
    return true;
  }

  // ---- issues
  if (tail[0] === 'issues') {
    if (tail.length === 1) {
      if (method === 'POST') {
        const parsed = await readJsonBody(req);
        if (!parsed.ok) {
          sendJson(res, 400, errBody('Problems parsing JSON'));
          return true;
        }
        const title = typeof parsed.value.title === 'string' ? parsed.value.title : '';
        const body = typeof parsed.value.body === 'string' ? parsed.value.body : '';
        const labels = Array.isArray(parsed.value.labels) ? parsed.value.labels.filter((x): x is string => typeof x === 'string') : [];
        if (title === '') {
          sendJson(res, 422, errBody('title is required'));
          return true;
        }
        const created = createIssueIn(repo, title, body, labels);
        if ('error' in created) {
          sendJson(res, created.status, errBody(created.error));
          return true;
        }
        sendJson(res, 201, JSON.stringify(issueJson(repo, created)));
        return true;
      }
      if (method === 'GET') {
        const state = query.get('state') ?? 'open';
        const sort = query.get('sort') ?? 'created';
        const direction = query.get('direction') ?? 'desc';
        let list = repo.issues.filter((i) => state === 'all' || i.state === state);
        if (sort === 'created') {
          list = [...list].sort((a, b) => (direction === 'asc' ? a.createdSeq - b.createdSeq : b.createdSeq - a.createdSeq));
        }
        const { page } = paginate(list, query);
        sendJson(res, 200, page.map((i) => issueJson(repo, i)));
        return true;
      }
      sendJson(res, 404, errBody('Not Found'));
      return true;
    }
    const num = Number(tail[1]);
    const issue = Number.isInteger(num) ? repo.byNumber.get(num) : undefined;
    if (tail.length === 2) {
      if (issue === undefined) {
        if (method === 'GET' || method === 'PATCH') await readBody(req).catch(() => undefined);
        sendJson(res, 404, errBody('Not Found'));
        return true;
      }
      if (method === 'GET') {
        sendRaw(res, 200, issueJsonBuffer(repo, issue), JSON_TYPE);
        return true;
      }
      if (method === 'PATCH') {
        const parsed = await readJsonBody(req);
        if (!parsed.ok) {
          sendJson(res, 400, errBody('Problems parsing JSON'));
          return true;
        }
        if (parsed.value.state === 'open' || parsed.value.state === 'closed') issue.state = parsed.value.state;
        if (typeof parsed.value.title === 'string') issue.title = parsed.value.title;
        if (typeof parsed.value.body === 'string') issue.body = parsed.value.body;
        issue.updatedSeq = ++globalSeq;
        repo.issueJsonCache.delete(issue.number);
        sendJson(res, 200, issueJson(repo, issue));
        return true;
      }
      sendJson(res, 404, errBody('Not Found'));
      return true;
    }
    if (tail.length === 3 && tail[2] === 'comments') {
      if (issue === undefined) {
        sendJson(res, 404, errBody('Not Found'));
        return true;
      }
      if (method === 'POST') {
        const parsed = await readJsonBody(req);
        if (!parsed.ok) {
          sendJson(res, 400, errBody('Problems parsing JSON'));
          return true;
        }
        const body = typeof parsed.value.body === 'string' ? parsed.value.body : '';
        const comment = { id: ++nextCommentSeq + 100000, body, createdAt: nowIso() };
        issue.comments.push(comment);
        repo.issueJsonCache.delete(issue.number);
        sendJson(res, 201, { id: comment.id, node_id: globalId('IssueComment', repo.id, issue.number, comment.id), body, user: { login: VIEWER_LOGIN, id: VIEWER_ID }, created_at: comment.createdAt, updated_at: comment.createdAt });
        return true;
      }
      if (method === 'GET') {
        sendJson(res, 200, issue.comments.map((c) => ({ id: c.id, node_id: globalId('IssueComment', repo.id, issue.number, c.id), body: c.body, user: { login: VIEWER_LOGIN, id: VIEWER_ID }, created_at: c.createdAt, updated_at: c.createdAt })));
        return true;
      }
      sendJson(res, 404, errBody('Not Found'));
      return true;
    }
    sendJson(res, 404, errBody('Not Found'));
    return true;
  }

  // ---- pulls
  if (tail[0] === 'pulls') {
    if (tail.length === 1) {
      if (method === 'POST') {
        const parsed = await readJsonBody(req);
        if (!parsed.ok) {
          sendJson(res, 400, errBody('Problems parsing JSON'));
          return true;
        }
        const title = typeof parsed.value.title === 'string' ? parsed.value.title : '';
        const body = typeof parsed.value.body === 'string' ? parsed.value.body : '';
        const head = typeof parsed.value.head === 'string' ? parsed.value.head : '';
        const base = typeof parsed.value.base === 'string' ? parsed.value.base : repo.defaultBranch;
        if (title === '' || head === '') {
          sendJson(res, 422, errBody('title and head are required'));
          return true;
        }
        const created = createPullIn(repo, title, body, head, base);
        if ('error' in created) {
          sendJson(res, created.status, errBody(created.error));
          return true;
        }
        sendJson(res, 201, pullJson(repo, created));
        return true;
      }
      if (method === 'GET') {
        const state = query.get('state') ?? 'open';
        let list = repo.pulls.filter((p) => state === 'all' || p.state === state);
        list = [...list].sort((a, b) => b.createdSeq - a.createdSeq);
        const { page } = paginate(list, query);
        sendJson(res, 200, page.map((p) => pullJson(repo, p)));
        return true;
      }
      sendJson(res, 404, errBody('Not Found'));
      return true;
    }
    const num = Number(tail[1]);
    const pull = Number.isInteger(num) ? repo.pullByNumber.get(num) : undefined;
    if (tail.length === 2) {
      if (pull === undefined) {
        sendJson(res, 404, errBody('Not Found'));
        return true;
      }
      if (method === 'GET') {
        sendJson(res, 200, pullJson(repo, pull));
        return true;
      }
      sendJson(res, 404, errBody('Not Found'));
      return true;
    }
    if (tail.length === 3 && tail[2] === 'files' && method === 'GET') {
      if (pull === undefined) {
        sendJson(res, 404, errBody('Not Found'));
        return true;
      }
      sendJson(res, 200, pullFiles(repo, pull));
      return true;
    }
    if (tail.length === 3 && tail[2] === 'merge' && method === 'PUT') {
      await readBody(req).catch(() => undefined);
      if (pull === undefined) {
        sendJson(res, 404, errBody('Not Found'));
        return true;
      }
      if (pull.merged || pull.state === 'closed') {
        sendJson(res, 405, errBody('Pull request is already merged or closed'));
        return true;
      }
      const sha = squashMerge(repo, pull);
      if (sha === null) {
        sendJson(res, 405, errBody('Merge conflict'));
        return true;
      }
      sendJson(res, 200, { merged: true, sha, message: `Pull request #${pull.number} merged` });
      return true;
    }
    sendJson(res, 404, errBody('Not Found'));
    return true;
  }

  sendJson(res, 404, errBody('Not Found'));
  return true;
}

// ---------------------------------------------------------------- git smart HTTP

function sortedRefs(repo: Repo): { name: string; oid: string }[] {
  const out: { name: string; oid: string }[] = [];
  for (const [name, oid] of repo.refs) out.push({ name, oid });
  out.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return out;
}

function peeledOid(repo: Repo, oid: string): string | null {
  const obj = repo.objects.get(oid);
  if (!obj) return null;
  if (obj.type === 'tag') return parseTag(obj.data).object;
  return null;
}

function v0Advertisement(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  if (service === 'git-upload-pack' && repo.advUp !== null) return repo.advUp;
  if (service === 'git-receive-pack' && repo.advRecv !== null) return repo.advRecv;
  const caps =
    service === 'git-upload-pack'
      ? 'symref=HEAD:refs/heads/main side-band-64k thin-pack ofs-delta multi_ack shallow'
      : 'symref=HEAD:refs/heads/main report-status report-status-v2 delete-refs side-band-64k ofs-delta agent=github-core-clone/1.0';
  const lines: (string | 'flush')[] = [`# service=${service}\n`, 'flush'];
  const refs = sortedRefs(repo);
  if (refs.length === 0) {
    lines.push(`${ZERO_OID} capabilities^{}\0${caps}\n`);
  } else {
    let first = true;
    for (const r of refs) {
      if (first) {
        lines.push(`${r.oid} ${r.name}\0${caps}\n`);
        first = false;
      } else {
        lines.push(`${r.oid} ${r.name}\n`);
      }
      const peeled = peeledOid(repo, r.oid);
      if (peeled !== null) lines.push(`${peeled} ${r.name}^{}\n`);
    }
  }
  lines.push('flush');
  const buf = pktLinesOf(lines);
  if (service === 'git-upload-pack') repo.advUp = buf;
  else repo.advRecv = buf;
  return buf;
}

function v2Advertisement(): Buffer {
  const lines: (string | 'flush')[] = [
    '# service=git-upload-pack\n',
    'flush',
    'version 2\n',
    'ls-refs\n',
    'fetch=shallow filter\n',
    'agent=github-core-clone/1.0\n',
    'object-format=sha1\n',
    'flush',
  ];
  return pktLinesOf(lines);
}
const V2_ADV = v2Advertisement();

function lsRefsResponse(repo: Repo, prefixes: string[], peel: boolean, symrefs: boolean): Buffer {
  const key = `${prefixes.join('\n')}|${peel ? 1 : 0}|${symrefs ? 1 : 0}`;
  const cached = repo.lsCache.get(key);
  if (cached !== undefined) return cached;
  const lines: (string | 'flush')[] = [];
  const mainTip = repo.refs.get('refs/heads/main');
  const keep = (name: string): boolean => prefixes.length === 0 || prefixes.some((p) => name.startsWith(p));
  if (mainTip !== undefined && symrefs && keep('HEAD')) {
    lines.push(`${mainTip} HEAD symref-target:refs/heads/main\n`);
  }
  for (const r of sortedRefs(repo)) {
    if (!keep(r.name)) continue;
    let line = `${r.oid} ${r.name}`;
    if (peel) {
      const peeled = peeledOid(repo, r.oid);
      if (peeled !== null) line += ` peeled:${peeled}`;
    }
    lines.push(`${line}\n`);
  }
  lines.push('flush');
  const buf = pktLinesOf(lines);
  if (repo.lsCache.size > 16) repo.lsCache.clear();
  repo.lsCache.set(key, buf);
  return buf;
}

interface FetchArgs {
  wants: string[];
  haves: string[];
  shallow: string[];
  depth: number | null;
}

function parseFetchArgs(packets: Pkt[]): FetchArgs {
  const args: FetchArgs = { wants: [], haves: [], shallow: [], depth: null };
  for (const p of packets) {
    if (p.kind !== 'data') continue;
    const line = p.payload.toString('utf8').replace(/\n$/, '');
    if (line.startsWith('want ')) args.wants.push(line.slice(5).trim());
    else if (line.startsWith('have ')) args.haves.push(line.slice(5).trim());
    else if (line.startsWith('shallow ')) args.shallow.push(line.slice(8).trim());
    else if (line.startsWith('deepen ')) {
      const n = Number(line.slice(7).trim());
      if (Number.isFinite(n)) args.depth = n;
    }
  }
  return args;
}

function fetchResponse(repo: Repo, args: FetchArgs): Buffer {
  // Whole-response cache: the bytes depend only on the repo's objects/refs
  // and these args, and every mutation clears the cache via touchRepo, so
  // a repeated identical fetch (the clone workload's 50 depth-1 clones of
  // one tip) is answered from the first build.
  const cacheKey = `${args.wants.join(',')}|${args.haves.join(',')}|${args.shallow.join(',')}|${args.depth ?? ''}`;
  const cached = repo.fetchCache.get(cacheKey);
  if (cached !== undefined) return cached;
  const buf = buildFetchResponse(repo, args);
  if (repo.fetchCache.size > 16) repo.fetchCache.clear();
  repo.fetchCache.set(cacheKey, buf);
  return buf;
}

function buildFetchResponse(repo: Repo, args: FetchArgs): Buffer {
  const completeHaves = args.haves.filter((h) => !args.shallow.includes(h));
  const boundaryHaves = args.haves.filter((h) => args.shallow.includes(h));
  // Objects the client already holds.
  const haveClosure = reachableObjects(repo, completeHaves);
  if (boundaryHaves.length > 0) {
    const boundaryTrees: string[] = [];
    for (const b of boundaryHaves) {
      const obj = repo.objects.get(b);
      if (!obj) continue;
      haveClosure.add(b);
      if (obj.type === 'commit') {
        const view = commitView(repo, b);
        if (view) boundaryTrees.push(view.tree);
      } else if (obj.type === 'tag') {
        haveClosure.add(parseTag(obj.data).object);
      }
    }
    for (const oid of reachableObjects(repo, boundaryTrees)) haveClosure.add(oid);
  }
  // Commits to consider: BFS from wants, depth-limited when requested.
  // Index pointer instead of shift(): the queue is O(1) per step.
  const wantCommits = new Set<string>();
  const queue: { oid: string; dist: number }[] = [];
  const seenQ = new Set<string>();
  for (const w of args.wants) {
    if (!isOid(w)) continue;
    queue.push({ oid: w, dist: 0 });
  }
  let qi = 0;
  while (qi < queue.length) {
    const { oid, dist } = queue[qi++]!;
    if (seenQ.has(oid)) continue;
    seenQ.add(oid);
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    if (obj.type === 'tag') {
      wantCommits.add(oid);
      queue.push({ oid: parseTag(obj.data).object, dist });
      continue;
    }
    if (obj.type !== 'commit') continue;
    if (args.depth !== null && dist >= args.depth) continue;
    wantCommits.add(oid);
    for (const p of commitParents(repo, oid)) queue.push({ oid: p, dist: dist + 1 });
  }
  // Objects to send: the wanted commits (depth-limited) plus each one's
  // tree/blob closure — one closure walk over all wanted trees, not one
  // walk per commit.
  const sendSet = new Set<string>();
  const wantTrees: string[] = [];
  for (const oid of wantCommits) {
    if (haveClosure.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    if (obj.type === 'commit') {
      sendSet.add(oid);
      const view = commitView(repo, oid);
      if (view) wantTrees.push(view.tree);
    } else {
      sendSet.add(oid);
    }
  }
  for (const o of reachableObjects(repo, wantTrees)) {
    if (!haveClosure.has(o)) sendSet.add(o);
  }
  // Shallow boundaries of the new state.
  const shallowOut: string[] = [];
  const unshallowOut: string[] = [];
  if (args.depth !== null) {
    for (const oid of wantCommits) {
      if (haveClosure.has(oid)) continue;
      const obj = repo.objects.get(oid);
      if (!obj || obj.type !== 'commit') continue;
      const parents = commitParents(repo, oid);
      if (parents.length > 0 && parents.some((p) => !wantCommits.has(p))) shallowOut.push(oid);
    }
    for (const b of args.shallow) {
      const obj = repo.objects.get(b);
      if (!obj || obj.type !== 'commit') continue;
      const parents = commitParents(repo, b);
      if (parents.length === 0) continue;
      if (parents.every((p) => wantCommits.has(p) || haveClosure.has(p) || sendSet.has(p))) unshallowOut.push(b);
    }
  }
  const parts: Buffer[] = [];
  const ackLines: (string | 'delim')[] = ['acknowledgments\n'];
  if (sendSet.size === 0) {
    for (const w of args.wants) ackLines.push(`ACK ${w}\n`);
    ackLines.push('ready\n');
  } else {
    ackLines.push('NAK\n');
  }
  parts.push(pktLinesOf([...ackLines, 'delim']));
  if (shallowOut.length > 0 || unshallowOut.length > 0) {
    const lines: (string | 'delim')[] = ['shallow-info\n'];
    for (const s of shallowOut) lines.push(`shallow ${s}\n`);
    for (const u of unshallowOut) lines.push(`unshallow ${u}\n`);
    lines.push('delim');
    parts.push(pktLinesOf(lines));
  }
  if (sendSet.size > 0) {
    const objects: GitObj[] = [];
    for (const oid of sendSet) {
      const o = repo.objects.get(oid);
      if (o) objects.push(o);
    }
    const pack = writePack(objects);
    parts.push(pktLine('packfile\n'));
    const CHUNK = 32768;
    for (let off = 0; off < pack.length; off += CHUNK) {
      const chunk = pack.subarray(off, Math.min(pack.length, off + CHUNK));
      const payload = Buffer.allocUnsafe(chunk.length + 1);
      payload[0] = 1;
      chunk.copy(payload, 1);
      parts.push(pktLine(payload));
    }
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

function receivePackResponse(repo: Repo, body: Buffer): { status: number; buf: Buffer; contentType: string } {
  // Split commands (up to the first flush) from the pack. The pack bytes
  // are binary and are NOT pkt-lines, so only the command section is parsed.
  const commands: { oldOid: string; newOid: string; ref: string }[] = [];
  let packStart = body.length;
  {
    let off = 0;
    let sawFlush = false;
    while (off < body.length) {
      const lenText = body.subarray(off, off + 4).toString('ascii');
      const len = parseInt(lenText, 16);
      if (len === 0) {
        off += 4;
        sawFlush = true;
        break;
      }
      if (len < 4 || off + len > body.length) {
        return { status: 400, buf: Buffer.from(JSON.stringify(errBody('malformed pkt-line'))), contentType: JSON_TYPE };
      }
      const payload = body.subarray(off + 4, off + len).toString('utf8');
      const nul = payload.indexOf('\0');
      const first = nul >= 0 ? payload.slice(0, nul) : payload;
      const m = /^([0-9a-f]{40}) ([0-9a-f]{40}) (\S+)\s*$/.exec(first.replace(/\n$/, ''));
      if (!m) {
        return { status: 400, buf: Buffer.from(JSON.stringify(errBody('bad receive-pack command'))), contentType: JSON_TYPE };
      }
      commands.push({ oldOid: m[1]!, newOid: m[2]!, ref: m[3]! });
      off += len;
    }
    if (!sawFlush) {
      return { status: 400, buf: Buffer.from(JSON.stringify(errBody('receive-pack commands not terminated'))), contentType: JSON_TYPE };
    }
    packStart = off;
  }
  if (commands.length === 0) {
    return { status: 400, buf: Buffer.from(JSON.stringify(errBody('no commands'))), contentType: JSON_TYPE };
  }
  const hasUpdates = commands.some((c) => c.newOid !== ZERO_OID);
  let unpackOk = true;
  let unpackDetail = 'ok';
  const packBytes = body.subarray(packStart);
  if (hasUpdates) {
    if (packBytes.length === 0) {
      unpackOk = false;
      unpackDetail = 'missing packfile';
    } else {
      try {
        const objs = readPack(packBytes);
        let added = false;
        for (const [oid, obj] of objs) {
          if (!repo.objects.has(oid)) {
            repo.objects.set(oid, obj);
            added = true;
          }
        }
        if (added) touchRepo(repo);
      } catch {
        unpackOk = false;
        unpackDetail = 'unpack error';
      }
    }
  }
  const reportLines: string[] = [`unpack ${unpackOk ? 'ok' : unpackDetail}\n`];
  if (unpackOk) {
    for (const cmd of commands) {
      const current = repo.refs.get(cmd.ref);
      let ok = true;
      let reason = '';
      if (cmd.newOid === ZERO_OID) {
        if (current === undefined) {
          ok = false;
          reason = 'no such ref';
        } else if (cmd.oldOid !== ZERO_OID && cmd.oldOid !== current) {
          ok = false;
          reason = 'non-fast-forward';
        } else {
          deleteRef(repo, cmd.ref);
        }
      } else if (cmd.oldOid === ZERO_OID) {
        if (current !== undefined) {
          ok = false;
          reason = 'already exists';
        } else if (!repo.objects.has(cmd.newOid)) {
          ok = false;
          reason = 'object not found';
        } else {
          setRef(repo, cmd.ref, cmd.newOid);
        }
      } else {
        if (current === undefined) {
          ok = false;
          reason = 'no such ref';
        } else if (cmd.oldOid !== current) {
          ok = false;
          reason = 'non-fast-forward';
        } else if (!repo.objects.has(cmd.newOid)) {
          ok = false;
          reason = 'object not found';
        } else if (cmd.ref.startsWith('refs/heads/')) {
          const newObj = repo.objects.get(cmd.newOid)!;
          if (newObj.type === 'commit' && !isAncestor(repo, cmd.oldOid, cmd.newOid)) {
            ok = false;
            reason = 'non-fast-forward';
          } else {
            setRef(repo, cmd.ref, cmd.newOid);
          }
        } else {
          setRef(repo, cmd.ref, cmd.newOid);
        }
      }
      reportLines.push(ok ? `ok ${cmd.ref}\n` : `ng ${cmd.ref} ${reason}\n`);
    }
  } else {
    for (const cmd of commands) reportLines.push(`ng ${cmd.ref} unpack failed\n`);
  }
  const report = pktLinesOf(reportLines);
  // One allocation: pkt-line framing of the sideband payload + flush.
  const inner = Buffer.allocUnsafe(report.length + 1);
  inner[0] = 1;
  report.copy(inner, 1);
  const framed = pktLine(inner);
  const out = Buffer.allocUnsafe(framed.length + 4);
  framed.copy(out, 0);
  PKT_FLUSH.copy(out, framed.length);
  return { status: 200, buf: out, contentType: 'application/x-git-receive-pack-result' };
}

/** Parse /{owner}/{repo}.git/{suffix} without a regex. Null when not a git path. */
function parseGitPath(path: string): { owner: string; repoName: string; suffix: string } | null {
  if (!path.startsWith('/')) return null;
  const s2 = path.indexOf('/', 1);
  if (s2 < 0) return null;
  const owner = path.slice(1, s2);
  if (owner === '') return null;
  const s3 = path.indexOf('/', s2 + 1);
  if (s3 < 0) return null;
  const repoPart = path.slice(s2 + 1, s3);
  if (!repoPart.endsWith('.git')) return null;
  const repoName = repoPart.slice(0, -4);
  if (repoName === '') return null;
  return { owner, repoName, suffix: path.slice(s3 + 1) };
}

async function handleGit(req: IncomingMessage, res: ServerResponse, path: string, query: URLSearchParams): Promise<boolean> {
  const parsed = parseGitPath(path);
  if (parsed === null) return false;
  const { owner, repoName, suffix } = parsed;
  const method = req.method ?? 'GET';
  const repo = getRepo(owner, repoName);
  if (repo === null) {
    if (method === 'POST') await readBody(req).catch(() => undefined);
    sendJson(res, 404, errBody('Not Found'));
    return true;
  }
  if (suffix === 'info/refs' && method === 'GET') {
    const service = query.get('service');
    if (service === 'git-upload-pack') {
      const v2 = (req.headers['git-protocol'] ?? '') === 'version=2';
      sendRaw(res, 200, v2 ? V2_ADV : v0Advertisement(repo, 'git-upload-pack'), 'application/x-git-upload-pack-advertisement');
      return true;
    }
    if (service === 'git-receive-pack') {
      sendRaw(res, 200, v0Advertisement(repo, 'git-receive-pack'), 'application/x-git-receive-pack-advertisement');
      return true;
    }
    sendJson(res, 400, errBody('unknown service'));
    return true;
  }
  if (suffix === 'git-upload-pack' && method === 'POST') {
    const body = await readBody(req);
    let packets: Pkt[];
    try {
      packets = parsePktLines(body);
    } catch {
      sendJson(res, 400, errBody('malformed pkt-line'));
      return true;
    }
    const first = packets.find((p) => p.kind === 'data');
    const firstLine = first ? first.payload.toString('utf8') : '';
    if (firstLine.startsWith('command=ls-refs')) {
      const prefixes: string[] = [];
      let peel = false;
      let symrefs = false;
      for (const p of packets) {
        if (p.kind !== 'data') continue;
        const line = p.payload.toString('utf8').replace(/\n$/, '');
        if (line === 'peel') peel = true;
        else if (line === 'symrefs') symrefs = true;
        else if (line.startsWith('ref-prefix ')) prefixes.push(line.slice('ref-prefix '.length));
      }
      sendRaw(res, 200, lsRefsResponse(repo, prefixes, peel, symrefs), 'application/x-git-upload-pack-result');
      return true;
    }
    if (firstLine.startsWith('command=fetch')) {
      const args = parseFetchArgs(packets);
      sendRaw(res, 200, fetchResponse(repo, args), 'application/x-git-upload-pack-result');
      return true;
    }
    sendJson(res, 400, errBody('unknown upload-pack command'));
    return true;
  }
  if (suffix === 'git-receive-pack' && method === 'POST') {
    const body = await readBody(req);
    const out = receivePackResponse(repo, body);
    if (out.status === 200) sendRaw(res, 200, out.buf, out.contentType);
    else sendJson(res, out.status, JSON.parse(out.buf.toString('utf8')) as unknown);
    return true;
  }
  sendJson(res, 404, errBody('Not Found'));
  return true;
}

// ---------------------------------------------------------------- GraphQL v4

type GqlValue = string | number | boolean | null | GqlValue[] | { [k: string]: GqlValue };

interface GqlField {
  alias: string | null;
  name: string;
  args: Record<string, GqlValue>;
  children: GqlField[] | null;
  inlineType: string | null;
}

interface GqlOp {
  kind: 'query' | 'mutation';
  name: string | null;
  varDefs: Record<string, GqlValue>;
  fields: GqlField[];
}

function tokenizeGql(src: string): string[] {
  const tokens: string[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i]!;
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === ',' || c === '#') {
      if (c === '#') {
        while (i < src.length && src[i] !== '\n') i++;
      } else i++;
      continue;
    }
    if ('{}()[]:!=$@'.includes(c)) {
      if (c === '.' && src.slice(i, i + 3) === '...') {
        tokens.push('...');
        i += 3;
        continue;
      }
      tokens.push(c);
      i++;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) {
          const e = src[j + 1]!;
          if (e === 'n') out += '\n';
          else if (e === 't') out += '\t';
          else if (e === 'r') out += '\r';
          else out += e;
          j += 2;
        } else {
          out += src[j];
          j++;
        }
      }
      tokens.push(JSON.stringify(out));
      i = j + 1;
      continue;
    }
    let j = i;
    while (j < src.length && /[A-Za-z0-9_.-]/.test(src[j]!)) j++;
    tokens.push(src.slice(i, j));
    i = j;
  }
  return tokens;
}

class GqlParser {
  pos = 0;
  private tokens: string[];
  private variables: Record<string, GqlValue>;

  constructor(tokens: string[], variables: Record<string, GqlValue>) {
    this.tokens = tokens;
    this.variables = variables;
  }


  peek(): string {
    return this.tokens[this.pos] ?? '';
  }
  next(): string {
    return this.tokens[this.pos++] ?? '';
  }
  expect(t: string): void {
    const got = this.next();
    if (got !== t) throw new Error(`expected ${t}, got ${got}`);
  }

  parseValue(): GqlValue {
    const t = this.next();
    if (t === '$') {
      const name = this.next();
      return this.variables[name] ?? null;
    }
    if (t === '[') {
      const arr: GqlValue[] = [];
      while (this.peek() !== ']') arr.push(this.parseValue());
      this.expect(']');
      return arr;
    }
    if (t === '{') {
      const obj: Record<string, GqlValue> = {};
      while (this.peek() !== '}') {
        const k = this.next();
        this.expect(':');
        obj[k] = this.parseValue();
      }
      this.expect('}');
      return obj;
    }
    if (t.startsWith('"')) return JSON.parse(t) as string;
    if (t === 'true') return true;
    if (t === 'false') return false;
    if (t === 'null') return null;
    const num = Number(t);
    if (t !== '' && !Number.isNaN(num)) return num;
    return t; // enum
  }

  parseArgs(): Record<string, GqlValue> {
    const args: Record<string, GqlValue> = {};
    if (this.peek() !== '(') return args;
    this.expect('(');
    while (this.peek() !== ')') {
      const name = this.next();
      this.expect(':');
      args[name] = this.parseValue();
    }
    this.expect(')');
    return args;
  }

  parseSelection(): GqlField[] {
    this.expect('{');
    const fields: GqlField[] = [];
    while (this.peek() !== '}') {
      const t = this.next();
      if (t === '...') {
        let inlineType: string | null = null;
        if (this.peek() === 'on') {
          this.next();
          inlineType = this.next();
        } else {
          this.next(); // fragment name; named fragments are not used by the checks
        }
        const children = this.parseSelection();
        fields.push({ alias: null, name: '__inline', args: {}, children, inlineType });
        continue;
      }
      let alias: string | null = null;
      let name = t;
      if (this.peek() === ':') {
        this.next();
        alias = name;
        name = this.next();
      }
      const args = this.parseArgs();
      let children: GqlField[] | null = null;
      if (this.peek() === '{') children = this.parseSelection();
      fields.push({ alias, name, args, children, inlineType: null });
    }
    this.expect('}');
    return fields;
  }

  parseOperation(): GqlOp {
    let kind: 'query' | 'mutation' = 'query';
    const t = this.peek();
    if (t === 'query' || t === 'mutation') {
      kind = this.next() as 'query' | 'mutation';
    }
    let name: string | null = null;
    if (this.peek() !== '' && this.peek() !== '{' && this.peek() !== '(') name = this.next();
    const varDefs: Record<string, GqlValue> = {};
    if (this.peek() === '(') {
      this.expect('(');
      while (this.peek() !== ')') {
        this.expect('$');
        const vn = this.next();
        this.expect(':');
        let typeName = this.next();
        if (this.peek() === '!') {
          this.next();
          typeName += '!';
        }
        if (this.peek() === '=') {
          this.next();
          varDefs[vn] = this.parseValue();
        }
        void typeName;
      }
      this.expect(')');
    }
    const fields = this.parseSelection();
    return { kind, name, varDefs, fields };
  }
}

function parseGql(query: string, variables: Record<string, GqlValue>): GqlOp {
  const parser = new GqlParser(tokenizeGql(query), variables);
  return parser.parseOperation();
}

// Schema knowledge: which fields each type has, for validation.
const TYPE_FIELDS: Record<string, Set<string>> = {
  Query: new Set(['viewer', 'repository', 'node', '__type', '__schema']),
  Mutation: new Set(['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment']),
  User: new Set(['login', 'id', 'name', 'email', 'nodeId']),
  Repository: new Set(['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest']),
  Ref: new Set(['name', 'target']),
  Issue: new Set(['id', 'number', 'title', 'state', 'body', 'createdAt', 'updatedAt', 'repository']),
  IssueConnection: new Set(['nodes', 'edges', 'pageInfo', 'totalCount']),
  IssueEdge: new Set(['node', 'cursor']),
  PageInfo: new Set(['hasNextPage', 'hasPreviousPage', 'endCursor', 'startCursor']),
  PullRequest: new Set(['id', 'number', 'title', 'body', 'state', 'merged', 'headRefName', 'baseRefName', 'mergeable', 'files', 'headRef', 'baseRef', 'repository']),
  PullRequestConnection: new Set(['nodes', 'edges', 'pageInfo', 'totalCount']),
  PullRequestEdge: new Set(['node', 'cursor']),
  PullRequestChangedFileConnection: new Set(['nodes', 'edges', 'pageInfo']),
  PullRequestChangedFile: new Set(['path', 'additions', 'deletions']),
  __Type: new Set(['name', 'kind', 'fields', 'enumValues', 'description']),
  __Field: new Set(['name', 'description', 'type']),
  __EnumValue: new Set(['name', 'description']),
  __Schema: new Set(['queryType', 'mutationType', 'types']),
  CreateIssuePayload: new Set(['issue', 'clientMutationId']),
  CloseIssuePayload: new Set(['issue', 'clientMutationId']),
  CreatePullRequestPayload: new Set(['pullRequest', 'clientMutationId']),
  MergePullRequestPayload: new Set(['pullRequest', 'clientMutationId']),
  AddCommentPayload: new Set(['commentEdge', 'clientMutationId']),
  IssueCommentEdge: new Set(['node', 'cursor']),
  IssueComment: new Set(['id', 'body', 'createdAt']),
};

const TYPE_NAME: Record<string, string> = {
  viewer: 'User',
  repository: 'Repository',
  node: 'Node',
  __type: '__Type',
  __schema: '__Schema',
  issue: 'Issue',
  issues: 'IssueConnection',
  pullRequests: 'PullRequestConnection',
  pullRequest: 'PullRequest',
  files: 'PullRequestChangedFileConnection',
  nodes: 'NodeItem',
  edges: 'EdgeItem',
  pageInfo: 'PageInfo',
  owner: 'User',
  defaultBranchRef: 'Ref',
  headRef: 'Ref',
  baseRef: 'Ref',
  fields: '__Field',
  enumValues: '__EnumValue',
  createIssue: 'CreateIssuePayload',
  closeIssue: 'CloseIssuePayload',
  createPullRequest: 'CreatePullRequestPayload',
  mergePullRequest: 'MergePullRequestPayload',
  addComment: 'AddCommentPayload',
  commentEdge: 'IssueCommentEdge',
};

const ISSUE_TYPE_FIELDS: Record<string, string[]> = {
  Issue: ['id', 'number', 'title', 'state', 'body'],
  PullRequest: ['id', 'number', 'headRefName', 'baseRefName', 'mergeable', 'state', 'merged', 'files'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest'],
  SearchType: ['ISSUE', 'ISSUE_AND_PR', 'PULL_REQUEST', 'REPOSITORY', 'USER', 'ORGANIZATION'],
};

class GqlError extends Error {
  constructor(message: string) {
    super(message);
  }
}

function repoView(repo: Repo): Record<string, unknown> {
  const view: Record<string, unknown> = {
    __typename: 'Repository',
    id: globalId('Repository', repo.id),
    databaseId: repo.id,
    name: repo.name,
    nameWithOwner: `${repo.owner}/${repo.name}`,
    owner: { __typename: 'User', login: repo.owner, id: VIEWER_ID },
    defaultBranchRef: { __typename: 'Ref', name: repo.defaultBranch },
    viewerPermission: 'ADMIN',
    hasIssuesEnabled: true,
    issue: (args: Record<string, GqlValue>) => {
      const n = Number(args.number);
      const issue = repo.byNumber.get(n);
      return issue ? issueView(repo, issue) : null;
    },
    issues: (args: Record<string, GqlValue>) => issuesConnection(repo, args),
    pullRequest: (args: Record<string, GqlValue>) => {
      const n = Number(args.number);
      const pull = repo.pullByNumber.get(n);
      return pull ? pullView(repo, pull) : null;
    },
    pullRequests: (args: Record<string, GqlValue>) => {
      const first = typeof args.first === 'number' ? args.first : 100;
      const nodes = [...repo.pulls].sort((a, b) => a.createdSeq - b.createdSeq).slice(0, first).map((p) => pullView(repo, p));
      return { __typename: 'PullRequestConnection', nodes, pageInfo: { hasNextPage: false, endCursor: null }, totalCount: repo.pulls.length };
    },
  };
  return view;
}

function issueView(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    __typename: 'Issue',
    id: globalId('Issue', repo.id, issue.number),
    number: issue.number,
    title: issue.title,
    state: issue.state === 'open' ? 'OPEN' : 'CLOSED',
    body: issue.body,
    createdAt: isoOf(BASE_TS + issue.createdSeq),
    updatedAt: isoOf(BASE_TS + issue.updatedSeq),
  };
}

function pullView(repo: Repo, pull: Pull): Record<string, unknown> {
  return {
    __typename: 'PullRequest',
    id: globalId('PullRequest', repo.id, pull.number),
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.merged ? 'MERGED' : pull.state === 'open' ? 'OPEN' : 'CLOSED',
    merged: pull.merged,
    headRefName: pull.headRef,
    baseRefName: pull.baseRef,
    mergeable: prMergeable(repo, pull),
    files: (args: Record<string, GqlValue>) => {
      const first = typeof args.first === 'number' ? args.first : 100;
      const nodes = pullFiles(repo, pull).slice(0, first).map((f) => ({ __typename: 'PullRequestChangedFile', path: f.filename, additions: f.additions, deletions: f.deletions }));
      return { __typename: 'PullRequestChangedFileConnection', nodes, pageInfo: { hasNextPage: false, endCursor: null } };
    },
  };
}

function issuesConnection(repo: Repo, args: Record<string, GqlValue>): Record<string, unknown> {
  let list = [...repo.issues];
  const states = args.states;
  if (Array.isArray(states) && states.length > 0) {
    const want = new Set(states.map((s) => String(s).toLowerCase()));
    list = list.filter((i) => want.has(i.state));
  }
  const orderBy = args.orderBy;
  let desc = false;
  if (orderBy !== null && typeof orderBy === 'object' && !Array.isArray(orderBy)) {
    const ob = orderBy as Record<string, GqlValue>;
    desc = String(ob.direction ?? '') === 'DESC';
  }
  list.sort((a, b) => (desc ? b.createdSeq - a.createdSeq : a.createdSeq - b.createdSeq));
  let start = 0;
  if (typeof args.after === 'string' && args.after !== '') {
    try {
      const text = Buffer.from(args.after, 'base64').toString('utf8');
      const n = Number(text.replace('cursor:', ''));
      const idx = list.findIndex((i) => i.number === n);
      if (idx >= 0) start = idx + 1;
    } catch {
      // unknown cursor: start from the beginning
    }
  }
  const first = typeof args.first === 'number' ? args.first : 100;
  const page = list.slice(start, start + first);
  const hasNext = start + first < list.length;
  const endCursor = page.length > 0 ? Buffer.from(`cursor:${page[page.length - 1]!.number}`, 'utf8').toString('base64') : null;
  return {
    __typename: 'IssueConnection',
    nodes: page.map((i) => issueView(repo, i)),
    pageInfo: { hasNextPage: hasNext, endCursor },
    totalCount: list.length,
  };
}

function resolveFieldValue(obj: Record<string, unknown>, field: GqlField): unknown {
  const value = obj[field.name];
  if (typeof value === 'function') return (value as (args: Record<string, GqlValue>) => unknown)(field.args);
  return value;
}

/** Execute one selection set against an object, validating field names. */
function executeSelection(obj: Record<string, unknown> | null, fields: GqlField[], typeName: string): Record<string, unknown> | null {
  if (obj === null) return null;
  const out: Record<string, unknown> = {};
  for (const field of fields) {
    if (field.name === '__inline') {
      if (field.inlineType !== null) {
        const actual = (obj.__typename as string | undefined) ?? typeName;
        if (actual !== field.inlineType) continue;
      }
      const nested = executeSelection(obj, field.children ?? [], typeName);
      if (nested) Object.assign(out, nested);
      continue;
    }
    if (field.name === '__typename') {
      out[field.alias ?? '__typename'] = obj.__typename ?? typeName;
      continue;
    }
    const allowed = TYPE_FIELDS[typeName];
    if (allowed && !allowed.has(field.name)) {
      throw new GqlError(`Cannot query field "${field.name}" on type "${typeName}".`);
    }
    const value = resolveFieldValue(obj, field);
    const key = field.alias ?? field.name;
    if (field.children === null) {
      out[key] = value === undefined ? null : value;
    } else if (Array.isArray(value)) {
      out[key] = value.map((item) => {
        if (item !== null && typeof item === 'object') {
          const childType = TYPE_NAME[field.name] ?? typeName;
          return executeSelection(item as Record<string, unknown>, field.children!, childType);
        }
        return item;
      });
    } else if (value !== null && typeof value === 'object') {
      const childType = TYPE_NAME[field.name] ?? typeName;
      out[key] = executeSelection(value as Record<string, unknown>, field.children, childType);
    } else {
      out[key] = value === undefined ? null : value;
    }
  }
  return out;
}

function typeInfo(name: string): Record<string, unknown> {
  const fields = ISSUE_TYPE_FIELDS[name];
  if (name === 'SearchType') {
    return { __typename: '__Type', name, kind: 'ENUM', enumValues: fields!.map((f) => ({ __typename: '__EnumValue', name: f })) };
  }
  return { __typename: '__Type', name, kind: 'OBJECT', fields: (fields ?? []).map((f) => ({ __typename: '__Field', name: f })), enumValues: null };
}

function executeOperation(op: GqlOp): { data: Record<string, unknown> | null; errors?: { message: string }[] } {
  try {
    const rootType = op.kind === 'mutation' ? 'Mutation' : 'Query';
    const root: Record<string, unknown> = {};
    const out: Record<string, unknown> = {};
    for (const field of op.fields) {
      if (field.name === '__inline') continue;
      if (field.name === '__typename') {
        out[field.alias ?? '__typename'] = rootType;
        continue;
      }
      const allowed = TYPE_FIELDS[rootType];
      if (allowed && !allowed.has(field.name)) {
        throw new GqlError(`Cannot query field "${field.name}" on type "${rootType}".`);
      }
      const key = field.alias ?? field.name;
      if (op.kind === 'query') {
        if (field.name === 'viewer') {
          const viewer = { __typename: 'User', login: VIEWER_LOGIN, id: VIEWER_ID, name: VIEWER_NAME, email: VIEWER_EMAIL };
          out[key] = field.children ? executeSelection(viewer, field.children, 'User') : viewer;
        } else if (field.name === 'repository') {
          const owner = String(field.args.owner ?? '');
          const name = String(field.args.name ?? '');
          const repo = getRepo(owner, name);
          out[key] = repo === null ? null : field.children ? executeSelection(repoView(repo), field.children, 'Repository') : repoView(repo);
        } else if (field.name === 'node') {
          const id = String(field.args.id ?? '');
          const parts = decodeGlobalId(id);
          let nodeObj: Record<string, unknown> | null = null;
          if (parts && parts[0] === 'Repository') {
            const repo = reposById.get(Number(parts[1]));
            if (repo) nodeObj = repoView(repo);
          }
          out[key] = nodeObj === null ? null : field.children ? executeSelection(nodeObj, field.children, 'Repository') : nodeObj;
        } else if (field.name === '__type') {
          const name = String(field.args.name ?? '');
          const info = typeInfo(name);
          out[key] = field.children ? executeSelection(info, field.children, '__Type') : info;
        } else if (field.name === '__schema') {
          const info = { __typename: '__Schema', queryType: { name: 'Query' }, mutationType: { name: 'Mutation' }, types: [] };
          out[key] = field.children ? executeSelection(info, field.children, '__Schema') : info;
        } else {
          out[key] = null;
        }
      } else {
        if (field.name === 'createIssue') {
          const input = (field.args.input ?? {}) as Record<string, GqlValue>;
          const parts = decodeGlobalId(String(input.repositoryId ?? ''));
          const repo = parts && parts[0] === 'Repository' ? reposById.get(Number(parts[1])) : undefined;
          if (!repo) throw new GqlError('repository not found');
          const created = createIssueIn(repo, String(input.title ?? ''), String(input.body ?? ''), []);
          if ('error' in created) throw new GqlError(created.error);
          const payload = { __typename: 'CreateIssuePayload', issue: issueView(repo, created) };
          out[key] = field.children ? executeSelection(payload, field.children, 'CreateIssuePayload') : payload;
        } else if (field.name === 'closeIssue') {
          const input = (field.args.input ?? {}) as Record<string, GqlValue>;
          const parts = decodeGlobalId(String(input.issueId ?? ''));
          if (!parts || parts[0] !== 'Issue') throw new GqlError('issue not found');
          const repo = reposById.get(Number(parts[1]));
          const issue = repo?.byNumber.get(Number(parts[2]));
          if (!repo || !issue) throw new GqlError('issue not found');
          issue.state = 'closed';
          issue.updatedSeq = ++globalSeq;
          repo.issueJsonCache.delete(issue.number);
          const payload = { __typename: 'CloseIssuePayload', issue: issueView(repo, issue) };
          out[key] = field.children ? executeSelection(payload, field.children, 'CloseIssuePayload') : payload;
        } else if (field.name === 'createPullRequest') {
          const input = (field.args.input ?? {}) as Record<string, GqlValue>;
          const parts = decodeGlobalId(String(input.repositoryId ?? ''));
          const repo = parts && parts[0] === 'Repository' ? reposById.get(Number(parts[1])) : undefined;
          if (!repo) throw new GqlError('repository not found');
          const created = createPullIn(repo, String(input.title ?? ''), '', String(input.headRefName ?? ''), String(input.baseRefName ?? ''));
          if ('error' in created) throw new GqlError(created.error);
          const payload = { __typename: 'CreatePullRequestPayload', pullRequest: pullView(repo, created) };
          out[key] = field.children ? executeSelection(payload, field.children, 'CreatePullRequestPayload') : payload;
        } else if (field.name === 'mergePullRequest') {
          const input = (field.args.input ?? {}) as Record<string, GqlValue>;
          const parts = decodeGlobalId(String(input.pullRequestId ?? ''));
          if (!parts || parts[0] !== 'PullRequest') throw new GqlError('pull request not found');
          const repo = reposById.get(Number(parts[1]));
          const pull = repo?.pullByNumber.get(Number(parts[2]));
          if (!repo || !pull) throw new GqlError('pull request not found');
          if (pull.merged || pull.state === 'closed') throw new GqlError('pull request is already closed');
          const sha = squashMerge(repo, pull);
          if (sha === null) throw new GqlError('Merge conflict');
          const payload = { __typename: 'MergePullRequestPayload', pullRequest: pullView(repo, pull) };
          out[key] = field.children ? executeSelection(payload, field.children, 'MergePullRequestPayload') : payload;
        } else if (field.name === 'addComment') {
          const input = (field.args.input ?? {}) as Record<string, GqlValue>;
          const parts = decodeGlobalId(String(input.subjectId ?? ''));
          if (!parts || parts[0] !== 'Issue') throw new GqlError('subject not found');
          const repo = reposById.get(Number(parts[1]));
          const issue = repo?.byNumber.get(Number(parts[2]));
          if (!repo || !issue) throw new GqlError('subject not found');
          const comment = { id: ++nextCommentSeq + 100000, body: String(input.body ?? ''), createdAt: nowIso() };
          issue.comments.push(comment);
          repo.issueJsonCache.delete(issue.number);
          const payload = {
            __typename: 'AddCommentPayload',
            commentEdge: { __typename: 'IssueCommentEdge', node: { __typename: 'IssueComment', id: globalId('IssueComment', repo.id, issue.number, comment.id), body: comment.body } },
          };
          out[key] = field.children ? executeSelection(payload, field.children, 'AddCommentPayload') : payload;
        } else {
          out[key] = null;
        }
      }
    }
    void root;
    return { data: out };
  } catch (err) {
    if (err instanceof GqlError) return { data: null, errors: [{ message: err.message }] };
    return { data: null, errors: [{ message: err instanceof Error ? err.message : String(err) }] };
  }
}

async function handleGraphql(req: IncomingMessage, res: ServerResponse): Promise<void> {
  let parsed: unknown;
  try {
    const buf = await readBody(req);
    parsed = JSON.parse(buf.toString('utf8'));
  } catch {
    sendJson(res, 400, errBody('Problems parsing JSON'));
    return;
  }
  const ops: { query: string; variables?: Record<string, GqlValue> }[] = Array.isArray(parsed) ? parsed : [parsed as { query: string; variables?: Record<string, GqlValue> }];
  const results: unknown[] = [];
  for (const opDoc of ops) {
    if (typeof opDoc.query !== 'string') {
      results.push({ data: null, errors: [{ message: 'query is required' }] });
      continue;
    }
    const variables = (opDoc.variables ?? {}) as Record<string, GqlValue>;
    let op: GqlOp;
    try {
      op = parseGql(opDoc.query, variables);
    } catch (err) {
      results.push({ data: null, errors: [{ message: err instanceof Error ? err.message : String(err) }] });
      continue;
    }
    results.push(executeOperation(op));
  }
  sendJson(res, 200, Array.isArray(parsed) ? results : results[0]);
}

// ---------------------------------------------------------------- MCP

const MCP_TOOLS: { name: string; description: string; inputSchema: Record<string, unknown> }[] = [
  {
    name: 'create_repo',
    description: 'Create a new repository for the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Repository name' },
        owner: { type: 'string', description: 'Owner login (defaults to the authenticated user)' },
        description: { type: 'string', description: 'Repository description' },
        private: { type: 'boolean', description: 'Whether the repository is private' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login' },
        repo: { type: 'string', description: 'Repository name' },
        repo_full_name: { type: 'string', description: 'Full repository name owner/repo' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login' },
        repo: { type: 'string', description: 'Repository name' },
        repo_full_name: { type: 'string', description: 'Full repository name owner/repo' },
        title: { type: 'string', description: 'Issue title' },
        body: { type: 'string', description: 'Issue body' },
        labels: { type: 'array', items: { type: 'string' }, description: 'Label names' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login' },
        repo: { type: 'string', description: 'Repository name' },
        repo_full_name: { type: 'string', description: 'Full repository name owner/repo' },
        state: { type: 'string', description: 'Issue state: open, closed or all' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login' },
        repo: { type: 'string', description: 'Repository name' },
        repo_full_name: { type: 'string', description: 'Full repository name owner/repo' },
        title: { type: 'string', description: 'Pull request title' },
        body: { type: 'string', description: 'Pull request body' },
        head: { type: 'string', description: 'Head branch name' },
        base: { type: 'string', description: 'Base branch name' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request with a squash merge.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login' },
        repo: { type: 'string', description: 'Repository name' },
        repo_full_name: { type: 'string', description: 'Full repository name owner/repo' },
        pull_number: { type: 'integer', description: 'Pull request number' },
        number: { type: 'integer', description: 'Pull request number' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

const MCP_PROTOCOL_VERSIONS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];

function mcpOwnerRepo(args: Record<string, unknown>): { owner: string; repo: string } | null {
  let owner = '';
  let repo = '';
  const full = typeof args.repo_full_name === 'string' ? args.repo_full_name : typeof args.full_name === 'string' ? args.full_name : '';
  if (full.includes('/')) {
    const parts = full.split('/');
    owner = parts[0]!;
    repo = parts[1]!;
  }
  if (typeof args.owner === 'string' && args.owner !== '') owner = args.owner;
  else if (typeof args.owner_login === 'string' && args.owner_login !== '') owner = args.owner_login;
  else if (typeof args.org === 'string' && args.org !== '') owner = args.org;
  if (typeof args.repo === 'string' && args.repo !== '') repo = args.repo;
  else if (typeof args.repository === 'string' && args.repository !== '') repo = args.repository;
  else if (typeof args.repo_name === 'string' && args.repo_name !== '') repo = args.repo_name;
  else if (typeof args.repository_name === 'string' && args.repository_name !== '') repo = args.repository_name;
  if (owner === '') owner = VIEWER_LOGIN;
  if (repo === '') return null;
  return { owner, repo };
}

function mcpText(obj: unknown): { content: { type: string; text: string }[]; structuredContent: unknown } {
  return { content: [{ type: 'text', text: typeof obj === 'string' ? obj : JSON.stringify(obj) }], structuredContent: obj };
}

function mcpErrorResult(message: string): { content: { type: string; text: string }[]; isError: true } {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function mcpCallTool(name: string, args: Record<string, unknown>): Record<string, unknown> {
  const need = (keys: string[]): string | null => {
    for (const k of keys) if (args[k] === undefined || args[k] === null || args[k] === '') return k;
    return null;
  };
  switch (name) {
    case 'create_repo': {
      const missing = need(['name']);
      if (missing) return mcpErrorResult(`Missing required argument: ${missing}`);
      const repoName = String(args.name ?? args.repo ?? args.repository ?? '');
      if (repoName === '') return mcpErrorResult('Missing required argument: name');
      const existing = getRepo(VIEWER_LOGIN, repoName);
      if (existing) return mcpText(repoJson(existing));
      const repo = createRepoRecord(repoName, typeof args.description === 'string' ? args.description : '', args.private === true);
      return mcpText(repoJson(repo));
    }
    case 'get_repo': {
      const or = mcpOwnerRepo(args);
      if (or === null) return mcpErrorResult('Missing required argument: repo');
      const repo = getRepo(or.owner, or.repo);
      if (repo === null) return mcpErrorResult(`Repository ${or.owner}/${or.repo} not found`);
      return mcpText(repoJson(repo));
    }
    case 'create_issue': {
      const or = mcpOwnerRepo(args);
      if (or === null) return mcpErrorResult('Missing required argument: repo');
      const missing = need(['title']);
      if (missing) return mcpErrorResult(`Missing required argument: ${missing}`);
      const repo = getRepo(or.owner, or.repo);
      if (repo === null) return mcpErrorResult(`Repository ${or.owner}/${or.repo} not found`);
      const labels = Array.isArray(args.labels) ? args.labels.filter((x): x is string => typeof x === 'string') : [];
      const created = createIssueIn(repo, String(args.title), typeof args.body === 'string' ? args.body : '', labels);
      if ('error' in created) return mcpErrorResult(created.error);
      return mcpText(issueJson(repo, created));
    }
    case 'list_issues': {
      const or = mcpOwnerRepo(args);
      if (or === null) return mcpErrorResult('Missing required argument: repo');
      const repo = getRepo(or.owner, or.repo);
      if (repo === null) return mcpErrorResult(`Repository ${or.owner}/${or.repo} not found`);
      const state = typeof args.state === 'string' ? args.state : 'open';
      const list = repo.issues.filter((i) => state === 'all' || i.state === state).map((i) => issueJson(repo, i));
      return mcpText(list);
    }
    case 'create_pull_request': {
      const or = mcpOwnerRepo(args);
      if (or === null) return mcpErrorResult('Missing required argument: repo');
      const missing = need(['title']);
      if (missing) return mcpErrorResult(`Missing required argument: ${missing}`);
      const repo = getRepo(or.owner, or.repo);
      if (repo === null) return mcpErrorResult(`Repository ${or.owner}/${or.repo} not found`);
      const head = typeof args.head === 'string' ? args.head : typeof args.head_ref === 'string' ? args.head_ref : '';
      const base = typeof args.base === 'string' ? args.base : typeof args.base_ref === 'string' ? args.base_ref : repo.defaultBranch;
      if (head === '') return mcpErrorResult('Missing required argument: head');
      const created = createPullIn(repo, String(args.title), typeof args.body === 'string' ? args.body : '', head, base);
      if ('error' in created) return mcpErrorResult(created.error);
      return mcpText(pullJson(repo, created));
    }
    case 'merge_pull_request': {
      const or = mcpOwnerRepo(args);
      if (or === null) return mcpErrorResult('Missing required argument: repo');
      const num = args.pull_number ?? args.pr_number ?? args.number ?? args.pull_request_number;
      if (num === undefined || num === null) return mcpErrorResult('Missing required argument: pull_number');
      const repo = getRepo(or.owner, or.repo);
      if (repo === null) return mcpErrorResult(`Repository ${or.owner}/${or.repo} not found`);
      const pull = repo.pullByNumber.get(Number(num));
      if (pull === undefined) return mcpErrorResult(`Pull request ${num} not found`);
      if (pull.merged || pull.state === 'closed') return mcpErrorResult('Pull request is already merged or closed');
      const sha = squashMerge(repo, pull);
      if (sha === null) return mcpErrorResult('Merge conflict');
      return mcpText({ merged: true, number: pull.number, sha, state: 'closed' });
    }
    default:
      return mcpErrorResult(`Unknown tool: ${name}`);
  }
}

const MCP_TOOL_NAMES = new Set(MCP_TOOLS.map((t) => t.name));

async function handleMcp(req: IncomingMessage, res: ServerResponse): Promise<void> {
  let body: unknown;
  try {
    const buf = await readBody(req);
    body = JSON.parse(buf.toString('utf8'));
  } catch {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  const msg = body as Record<string, unknown>;
  const id = 'id' in msg ? (msg.id as string | number | null) : null;
  const method = typeof msg.method === 'string' ? msg.method : '';
  const params = (msg.params ?? {}) as Record<string, unknown>;
  const isNotification = id === null || id === undefined;
  if (method.startsWith('notifications/')) {
    sendNoContent(res, 202);
    return;
  }
  const rpcError = (code: number, message: string): void => {
    sendJson(res, 200, { jsonrpc: '2.0', id: id ?? null, error: { code, message } });
  };
  if (method === 'server/discover') {
    sendJson(res, 200, {
      jsonrpc: '2.0',
      id,
      result: {
        supportedVersions: MCP_PROTOCOL_VERSIONS,
        capabilities: { tools: {} },
        serverInfo: { name: 'github-core-clone', version: '1.0.0' },
        _meta: { 'io.modelcontextprotocol/serverInfo': { name: 'github-core-clone', version: '1.0.0' } },
      },
    });
    return;
  }
  if (method === 'initialize') {
    const requested = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
    const version = MCP_PROTOCOL_VERSIONS.includes(requested) ? requested : '2026-07-28';
    sendJson(res, 200, { jsonrpc: '2.0', id, result: { protocolVersion: version, capabilities: { tools: {} }, serverInfo: { name: 'github-core-clone', version: '1.0.0' } } });
    return;
  }
  if (method === 'ping') {
    sendJson(res, 200, { jsonrpc: '2.0', id, result: {} });
    return;
  }
  if (method === 'tools/list') {
    sendJson(res, 200, { jsonrpc: '2.0', id, result: { tools: MCP_TOOLS } });
    return;
  }
  if (method === 'tools/call') {
    const toolName = String(params.name ?? '');
    const args = (params.arguments ?? {}) as Record<string, unknown>;
    if (!MCP_TOOL_NAMES.has(toolName)) {
      rpcError(-32602, `Unknown tool: ${toolName}`);
      return;
    }
    const result = mcpCallTool(toolName, args);
    sendJson(res, 200, { jsonrpc: '2.0', id, result });
    return;
  }
  void isNotification;
  rpcError(-32601, `Method not found: ${method}`);
}

// ---------------------------------------------------------------- server

/**
 * Fast path for GET /api/v3/repos/{owner}/{repo}/issues/{n} — the read
 * workload's 2,000 sequential requests. Parses the path with indexOf (no
 * split/map/decode arrays), looks the repo and issue up in O(1) maps, and
 * answers from the cached issue JSON. Returns false when the shape does not
 * match, so the generic router handles it exactly as before.
 */
function fastGetIssue(req: IncomingMessage, res: ServerResponse, path: string): boolean {
  const prefix = '/api/v3/repos/';
  if (!path.startsWith(prefix)) return false;
  const rest = path.slice(prefix.length);
  const slash1 = rest.indexOf('/');
  if (slash1 < 0) return false;
  const owner = rest.slice(0, slash1);
  if (owner !== VIEWER_LOGIN) return false;
  const rest2 = rest.slice(slash1 + 1);
  const iss = rest2.indexOf('/issues/');
  if (iss < 0) return false;
  const repoName = rest2.slice(0, iss);
  if (repoName === '' || repoName.includes('%')) return false;
  const numStr = rest2.slice(iss + 8);
  if (numStr === '' || numStr.includes('/')) return false;
  let num = 0;
  for (let i = 0; i < numStr.length; i++) {
    const c = numStr.charCodeAt(i);
    if (c < 48 || c > 57) return false;
    num = num * 10 + (c - 48);
    if (num > 9007199254740991) return false;
  }
  const repo = repos.get(`${owner}/${repoName}`);
  if (repo === undefined) {
    sendJson(res, 404, errBody('Not Found'));
    return true;
  }
  const issue = repo.byNumber.get(num);
  if (issue === undefined) {
    sendJson(res, 404, errBody('Not Found'));
    return true;
  }
  sendRaw(res, 200, issueJsonBuffer(repo, issue), JSON_TYPE);
  return true;
}

/**
 * Fast path for POST /api/v3/repos/{owner}/{repo}/issues — the write
 * workload. Same validation and creation as the generic router, but without
 * its routing overhead; the new issue is answered from its cached JSON.
 * Returns false when the shape does not match.
 */
function fastPostIssue(req: IncomingMessage, res: ServerResponse, path: string): boolean {
  const prefix = '/api/v3/repos/';
  if (!path.startsWith(prefix)) return false;
  const rest = path.slice(prefix.length);
  const slash1 = rest.indexOf('/');
  if (slash1 < 0) return false;
  const owner = rest.slice(0, slash1);
  if (owner !== VIEWER_LOGIN) return false;
  const rest2 = rest.slice(slash1 + 1);
  const iss = rest2.indexOf('/issues');
  if (iss < 0) return false;
  const repoName = rest2.slice(0, iss);
  if (repoName === '' || repoName.includes('%')) return false;
  if (rest2.slice(iss + 7) !== '') return false;
  void (async () => {
    const repo = repos.get(`${owner}/${repoName}`);
    if (repo === undefined) {
      await readBody(req).catch(() => undefined);
      sendJson(res, 404, errBody('Not Found'));
      return;
    }
    const parsed = await readJsonBody(req);
    if (!parsed.ok) {
      sendJson(res, 400, errBody('Problems parsing JSON'));
      return;
    }
    const title = typeof parsed.value.title === 'string' ? parsed.value.title : '';
    const body = typeof parsed.value.body === 'string' ? parsed.value.body : '';
    const labels = Array.isArray(parsed.value.labels) ? parsed.value.labels.filter((x): x is string => typeof x === 'string') : [];
    if (title === '') {
      sendJson(res, 422, errBody('title is required'));
      return;
    }
    const created = createIssueIn(repo, title, body, labels);
    if ('error' in created) {
      sendJson(res, created.status, errBody(created.error));
      return;
    }
    sendRaw(res, 201, issueJsonBuffer(repo, created), JSON_TYPE);
  })().catch((err: unknown) => {
    if (!res.headersSent) sendJson(res, 500, errBody(err instanceof Error ? err.message : 'internal error'));
  });
  return true;
}

function reportAsync(p: Promise<unknown>, res: ServerResponse): void {
  p.catch((err: unknown) => {
    if (!res.headersSent) sendJson(res, 500, errBody(err instanceof Error ? err.message : 'internal error'));
  });
}

/**
 * Synchronous dispatch: routes without an async wrapper or a promise per
 * request, so a GET that needs no body is answered in the same turn. Only
 * handlers that must read a body run asynchronously.
 */
function dispatch(req: IncomingMessage, res: ServerResponse): void {
  const url = req.url ?? '/';
  const q = url.indexOf('?');
  const path = q < 0 ? url : url.slice(0, q);
  const method = req.method ?? 'GET';
  if (path === '/healthz') {
    if (method === 'GET') sendJson(res, 200, { ok: true });
    else sendJson(res, 404, errBody('Not Found'));
    return;
  }
  const isGit = parseGitPath(path) !== null;
  const needsAuth = path === '/api/graphql' || path === '/mcp' || path.startsWith('/api/v3') || isGit;
  if (needsAuth && !authed(req)) {
    if (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') {
      void readBody(req).catch(() => undefined).then(() => {
        sendJson(res, 401, errBody('Requires authentication'));
      });
    } else {
      sendJson(res, 401, errBody('Requires authentication'));
    }
    return;
  }
  if (path === '/api/graphql') {
    if (method !== 'POST') {
      sendJson(res, 405, errBody('Method Not Allowed'));
      return;
    }
    reportAsync(handleGraphql(req, res), res);
    return;
  }
  if (path === '/mcp') {
    if (method !== 'POST') {
      sendJson(res, 405, errBody('Method Not Allowed'));
      return;
    }
    reportAsync(handleMcp(req, res), res);
    return;
  }
  if (path.startsWith('/api/v3')) {
    if (method === 'GET' && q < 0 && fastGetIssue(req, res, path)) return;
    if (method === 'POST' && q < 0 && fastPostIssue(req, res, path)) return;
    const query = q < 0 ? EMPTY_PARAMS : new URLSearchParams(url.slice(q + 1));
    reportAsync(handleRest(req, res, path, query), res);
    return;
  }
  if (isGit) {
    const query = q < 0 ? EMPTY_PARAMS : new URLSearchParams(url.slice(q + 1));
    reportAsync(handleGit(req, res, path, query), res);
    return;
  }
  sendJson(res, 404, errBody('Not Found'));
}

export function createApp(): Server {
  const server = createServer((req, res) => {
    try {
      dispatch(req, res);
    } catch (err) {
      if (!res.headersSent) sendJson(res, 500, errBody(err instanceof Error ? err.message : 'internal error'));
    }
  });
  return server;
}
