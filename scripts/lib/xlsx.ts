/**
 * Minimal, namespace-tolerant .xlsx-läsare (Office Open XML) utan tunga beroenden.
 * Hanterar: sharedStrings, inlineStr, str, n, b, d samt namnrymdsprefix (t.ex. "x:").
 * Formler läses som sitt cachade värde. Räcker för inventeringsarbetsboken och är
 * reproducerbar; stödjer inte makron, bilder eller stilar (behövs ej).
 */
import { readFileSync } from 'node:fs';
import { unzipSync, strFromU8 } from 'fflate';
import { XMLParser } from 'fast-xml-parser';

export interface XlsxCell {
  ref: string; // "B3"
  column: string; // "B"
  row: number; // 3
  value: string | null;
  type: string; // "str" | "s" | "inlineStr" | "n" | "b" | "d" | "e"
}
export interface XlsxSheet {
  name: string;
  index: number;
  rows: Map<number, Map<string, XlsxCell>>;
  maxRow: number;
  maxColumn: number;
}
export interface XlsxWorkbook {
  sheets: XlsxSheet[];
}

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  removeNSPrefix: true,
  isArray: (name) => ['sheet', 'row', 'c', 'si', 'r', 'Relationship'].includes(name),
  parseTagValue: false,
  trimValues: false,
});

function asArray<T>(v: T | T[] | undefined): T[] {
  if (v === undefined) return [];
  return Array.isArray(v) ? v : [v];
}

export function columnLetterToIndex(letters: string): number {
  let n = 0;
  for (const ch of letters) n = n * 26 + (ch.charCodeAt(0) - 64);
  return n;
}
export function columnIndexToLetter(index: number): string {
  let s = '';
  let n = index;
  while (n > 0) {
    const rem = (n - 1) % 26;
    s = String.fromCharCode(65 + rem) + s;
    n = Math.floor((n - 1) / 26);
  }
  return s;
}

function splitRef(ref: string): { column: string; row: number } {
  const m = /^([A-Z]+)(\d+)$/.exec(ref);
  if (!m) throw new Error(`Ogiltig cellreferens: ${ref}`);
  return { column: m[1]!, row: Number(m[2]) };
}

type AnyNode = Record<string, unknown>;

function textOf(node: unknown): string {
  if (node === null || node === undefined) return '';
  if (typeof node === 'string') return node;
  if (typeof node === 'number' || typeof node === 'boolean') return String(node);
  if (Array.isArray(node)) return node.map(textOf).join('');
  if (typeof node === 'object') {
    const o = node as AnyNode;
    if ('#text' in o) return textOf(o['#text']);
    // rich text: <r><t>..</t></r>, eller <t>
    if ('r' in o)
      return asArray(o['r'])
        .map((r) => textOf((r as AnyNode)['t']))
        .join('');
    if ('t' in o) return textOf(o['t']);
  }
  return '';
}

function readSharedStrings(files: Record<string, Uint8Array>): string[] {
  const f = files['xl/sharedStrings.xml'];
  if (!f) return [];
  const doc = parser.parse(strFromU8(f)) as AnyNode;
  const sst = doc['sst'] as AnyNode | undefined;
  if (!sst) return [];
  return asArray(sst['si']).map((si) => textOf(si));
}

export function readXlsx(path: string): XlsxWorkbook {
  const buf = readFileSync(path);
  const files = unzipSync(new Uint8Array(buf));
  const need = (name: string) => {
    const f = files[name];
    if (!f) throw new Error(`Saknar ${name} i arbetsboken`);
    return strFromU8(f);
  };

  const wbDoc = parser.parse(need('xl/workbook.xml')) as AnyNode;
  const wb = wbDoc['workbook'] as AnyNode;
  const sheetsNode = (wb['sheets'] as AnyNode) ?? {};
  const sheetDefs = asArray(sheetsNode['sheet']).map((s) => {
    const o = s as AnyNode;
    return { name: String(o['@_name']), rId: String(o['@_id'] ?? o['@_r:id'] ?? '') };
  });

  const relsDoc = parser.parse(need('xl/_rels/workbook.xml.rels')) as AnyNode;
  const rels = asArray(((relsDoc['Relationships'] as AnyNode) ?? {})['Relationship']).map((r) => {
    const o = r as AnyNode;
    return { id: String(o['@_Id']), target: String(o['@_Target']) };
  });
  const targetFor = (rId: string) => {
    const rel = rels.find((r) => r.id === rId);
    if (!rel) throw new Error(`Hittar ingen relation för ${rId}`);
    const t = rel.target.replace(/^\//, '');
    return t.startsWith('xl/') ? t : `xl/${t}`;
  };

  const shared = readSharedStrings(files);

  const sheets: XlsxSheet[] = sheetDefs.map((def, index) => {
    const xml = need(targetFor(def.rId));
    const doc = parser.parse(xml) as AnyNode;
    const ws = doc['worksheet'] as AnyNode;
    const sheetData = (ws['sheetData'] as AnyNode) ?? {};
    const rows = new Map<number, Map<string, XlsxCell>>();
    let maxRow = 0;
    let maxColumn = 0;
    for (const rowNode of asArray(sheetData['row'])) {
      const r = rowNode as AnyNode;
      const rowNum = Number(r['@_r']);
      const cells = new Map<string, XlsxCell>();
      for (const cNode of asArray(r['c'])) {
        const c = cNode as AnyNode;
        const ref = String(c['@_r']);
        const { column, row } = splitRef(ref);
        const type = String(c['@_t'] ?? 'n');
        let value: string | null = null;
        if (type === 's') {
          const idx = Number(textOf(c['v']));
          value = shared[idx] ?? null;
        } else if (type === 'inlineStr') {
          value = textOf(c['is']);
        } else if ('v' in c) {
          value = textOf(c['v']);
        }
        if (value !== null && value.trim() === '') value = null;
        cells.set(column, { ref, column, row, value, type });
        maxColumn = Math.max(maxColumn, columnLetterToIndex(column));
      }
      rows.set(rowNum, cells);
      maxRow = Math.max(maxRow, rowNum);
    }
    return { name: def.name, index, rows, maxRow, maxColumn };
  });

  return { sheets };
}
