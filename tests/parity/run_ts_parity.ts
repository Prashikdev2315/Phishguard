import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { extractFeatures } from "../../extension/src/lib/features";
import { loadModel, predictRisk } from "../../extension/src/lib/model";
import { normalize } from "../../extension/src/lib/normalize";

const root = resolve(import.meta.dirname, "../..");
const rows = readFileSync(resolve(root, "data/splits/test.csv"), "utf8")
  .trim().split(/\r?\n/).slice(1)
  .map((line) => line.split(",", 2)[0]);
const model = loadModel(readFileSync(resolve(root, "extension/public/model.bin")));
const result = rows.map((url) => {
  const normalized = normalize(url);
  const vector = Float32Array.from(Object.values(extractFeatures(url)));
  const verdict = predictRisk(model, vector);
  return { url, normalized, vector: Array.from(vector), risk: verdict.risk, probability: verdict.probability };
});
process.stdout.write(JSON.stringify(result));
