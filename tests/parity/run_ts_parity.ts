import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { extractFeatures } from "../../extension/src/lib/features";
import { loadModel, predictRisk } from "../../extension/src/lib/model";
import { normalize } from "../../extension/src/lib/normalize";

function parseFirstCsvField(line: string): string {
  if (line.startsWith('"')) {
    const match = line.match(/^"((?:[^"]|"")*)"/);
    if (match) {
      return match[1].replace(/""/g, '"');
    }
  }
  return line.split(",", 1)[0];
}

const root = resolve(import.meta.dirname, "../..");
const rows = readFileSync(resolve(root, "data/processed/D1_cleaned.csv"), "utf8")
  .trim().split(/\r?\n/).slice(1)
  .map(parseFirstCsvField);
const model = loadModel(readFileSync(resolve(root, "extension/public/model.bin")));
const result = rows.map((url) => {
  const normalized = normalize(url);
  const vector = Float64Array.from(Object.values(extractFeatures(url)));
  const verdict = predictRisk(model, vector);
  return { url, normalized, vector: Array.from(vector), risk: verdict.risk, probability: verdict.probability };
});
process.stdout.write(JSON.stringify(result));
