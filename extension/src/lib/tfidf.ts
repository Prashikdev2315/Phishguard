export interface TfidfModel {
  schema: "tfidf-url-v1";
  ngram_min: number;
  ngram_max: number;
  vocabulary: Record<string, number>;
  idf: number[];
  coefficient: number[];
  intercept: number;
}

function tokens(value: string, min: number, max: number): string[] {
  const result: string[] = [];
  for (const word of value.toLowerCase().split(/\s+/u).filter(Boolean)) {
    const padded = ` ${word} `;
    for (let size = min; size <= max; size++) {
      for (let index = 0; index + size <= padded.length; index++) {
        result.push(padded.slice(index, index + size));
      }
    }
  }
  return result;
}

export function predictTfidfProbability(model: TfidfModel, url: string): number {
  const counts = new Map<number, number>();
  for (const token of tokens(url, model.ngram_min, model.ngram_max)) {
    const index = model.vocabulary[token];
    if (index !== undefined) counts.set(index, (counts.get(index) ?? 0) + 1);
  }
  let squaredNorm = 0;
  const weighted = new Map<number, number>();
  for (const [index, count] of counts) {
    const value = count * model.idf[index];
    weighted.set(index, value);
    squaredNorm += value * value;
  }
  const norm = Math.sqrt(squaredNorm) || 1;
  let decision = model.intercept;
  for (const [index, value] of weighted) decision += (value / norm) * model.coefficient[index];
  return 1 / (1 + Math.exp(-decision));
}
