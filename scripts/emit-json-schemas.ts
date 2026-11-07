/** Exporterar JSON Schema (draft 2020-12) från Zod-scheman till schemas/json/. */
import { z } from 'zod';
import {
  Advisory,
  Claim,
  Control,
  Manifest,
  Observation,
  ProductFamily,
  ProductVulnerabilityMatch,
  ProtocolService,
  Source,
  Vendor,
  Vulnerability,
} from '../schemas/index';
import { p, writeJson } from './lib/fs';

const schemas: Record<string, z.ZodType> = {
  manifest: Manifest,
  vendor: Vendor,
  product_family: ProductFamily,
  protocol_service: ProtocolService,
  vulnerability: Vulnerability,
  advisory: Advisory,
  product_vulnerability_match: ProductVulnerabilityMatch,
  control: Control,
  source: Source,
  observation: Observation,
  claim: Claim,
};

for (const [name, schema] of Object.entries(schemas)) {
  const json = z.toJSONSchema(schema, { target: 'draft-2020-12', io: 'output' });
  writeJson(p('schemas', 'json', `${name}.schema.json`), {
    $id: `https://timpan8.github.io/ot-iot-security-intelligence/schemas/${name}.schema.json`,
    title: name,
    ...json,
  });
}
console.log(
  `JSON Schema exporterat för ${Object.keys(schemas).length} entiteter till schemas/json/`,
);
