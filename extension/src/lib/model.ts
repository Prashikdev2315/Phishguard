import { inflate } from "pako";
import { extractFeatures, extractVector } from "./features";
import { normalize } from "./normalize";
import { reasonCodes } from "./reasons";
import { RiskBand, RiskVerdict } from "./types";

export interface ModelHeader {
  schema: string;
  feature_count: number;
  k: number;
  calibration?: {
    method: "isotonic" | "platt";
    x_thresholds?: number[];
    y_thresholds?: number[];
    coefficient?: number;
    intercept?: number;
  };
  thresholds?: { T_block: number; T_warn: number };
}
interface Tree { left: Int32Array; right: Int32Array; feature: Int16Array; threshold: Float32Array; probabilities: Float32Array; }
export interface ExportedModel { header: ModelHeader; scalerMin: Float32Array; scalerScale: Float32Array; selected: Uint16Array; trees: Tree[]; }

const readJson = (bytes: Uint8Array): ModelHeader => JSON.parse(new TextDecoder().decode(bytes)) as ModelHeader;
export function loadModel(buffer: ArrayBuffer | Uint8Array): ExportedModel {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  if (new TextDecoder().decode(bytes.slice(0, 4)) !== "PGM1" || bytes[4] !== 1) throw new Error("Unsupported PGM1 model");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const headerLength = view.getUint32(5, true);
  const header = readJson(bytes.slice(9, 9 + headerLength));
  const payload = inflate(bytes.slice(9 + headerLength));
  let offset = 0;
  const scalerMin = new Float32Array(payload.buffer, payload.byteOffset + offset, 50); offset += 200;
  const scalerScale = new Float32Array(payload.buffer, payload.byteOffset + offset, 50); offset += 200;
  const selected = new Uint16Array(payload.buffer, payload.byteOffset + offset, 20); offset += 40;
  const trees: Tree[] = [];
  const readArray = <T extends Int32Array | Int16Array | Float32Array>(
    ctor: { new (buffer: ArrayBuffer): T },
    bytesPerItem: number,
    count: number,
  ): T => {
    const bytes = payload.slice(offset, offset + count * bytesPerItem);
    offset += count * bytesPerItem;
    return new ctor(bytes.buffer);
  };
  for (let t = 0; t < 200; t++) {
    const count = new DataView(payload.buffer, payload.byteOffset + offset, 4).getUint32(0, true); offset += 4;
    const left = readArray(Int32Array, 4, count);
    const right = readArray(Int32Array, 4, count);
    const feature = readArray(Int16Array, 2, count);
    const threshold = readArray(Float32Array, 4, count);
    const probabilities = readArray(Float32Array, 4, count);
    trees.push({ left, right, feature, threshold, probabilities });
  }
  return { header, scalerMin, scalerScale, selected, trees };
}

function calibrate(model: ExportedModel, raw: number): number {
  const calibration = model.header.calibration;
  if (!calibration) return raw;
  if (calibration.method === "platt") {
    const eps = Number.EPSILON;
    const clipped = Math.min(1 - eps, Math.max(eps, raw));
    const logit = Math.log(clipped / (1 - clipped));
    return 1 / (1 + Math.exp(-(Number(calibration.coefficient) * logit + Number(calibration.intercept))));
  }
  const x = calibration.x_thresholds ?? [];
  const y = calibration.y_thresholds ?? [];
  if (!x.length) return raw;
  if (raw <= x[0]) return y[0];
  if (raw >= x[x.length - 1]) return y[y.length - 1];
  let i = 1;
  while (i < x.length && raw > x[i]) i++;
  const fraction = (raw - x[i - 1]) / (x[i] - x[i - 1] || 1);
  return y[i - 1] + fraction * (y[i] - y[i - 1]);
}

export function predictProbability(model: ExportedModel, features: ArrayLike<number>): number {
  if (features.length !== model.header.feature_count) throw new Error("Expected 50 features");
  const selected = new Array<number>(model.selected.length);
  for (let i = 0; i < selected.length; i++) selected[i] = Number(features[model.selected[i]]) * model.scalerScale[model.selected[i]] + model.scalerMin[model.selected[i]];
  let probability = 0;
  for (const tree of model.trees) {
    let node = 0;
    while (tree.left[node] !== tree.right[node]) {
      node = selected[tree.feature[node]] <= tree.threshold[node] ? tree.left[node] : tree.right[node];
    }
    probability += tree.probabilities[node];
  }
  return calibrate(model, probability / model.trees.length);
}

export function predictRisk(model: ExportedModel, features: ArrayLike<number>): RiskVerdict {
  const probability = Math.min(1, Math.max(0, predictProbability(model, features)));
  const risk = Math.round(100 * probability);
  const band: RiskBand = risk < 35 ? "Safe" : risk < 70 ? "Suspicious" : "High-Risk";
  return { risk, probability, band, reasons: [] };
}

export function predictUrl(model: ExportedModel, url: string): RiskVerdict {
  const features = extractFeatures(url);
  const normalized = normalize(url);
  const verdict = predictRisk(model, extractVector(url));
  verdict.reasons = reasonCodes(verdict.risk, features, normalized);
  return verdict;
}
