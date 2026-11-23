// The few statistical tests the indistinguishability experiment needs.
// Plain JavaScript, no dependencies. Formulas follow Numerical Recipes.

function lnGamma(x) {
  const c = [76.18009172947146, -86.50532032941677, 24.01409824083091, -1.231739572450155, 0.1208650973866179e-2, -0.5395239384953e-5];
  let y = x;
  let tmp = x + 5.5;
  tmp -= (x + 0.5) * Math.log(tmp);
  let ser = 1.000000000190015;
  for (const cj of c) ser += cj / ++y;
  return -tmp + Math.log((2.5066282746310005 * ser) / x);
}

// Regularized upper incomplete gamma function Q(a, x).
export function gammaQ(a, x) {
  if (x <= 0) return 1;
  if (x < a + 1) {
    // series for P(a, x)
    let ap = a;
    let sum = 1 / a;
    let del = sum;
    for (let n = 0; n < 1000; n++) {
      ap += 1;
      del *= x / ap;
      sum += del;
      if (Math.abs(del) < Math.abs(sum) * 1e-15) break;
    }
    return 1 - sum * Math.exp(-x + a * Math.log(x) - lnGamma(a));
  }
  // continued fraction for Q(a, x)
  const tiny = 1e-300;
  let b = x + 1 - a;
  let c = 1 / tiny;
  let d = 1 / b;
  let h = d;
  for (let i = 1; i < 1000; i++) {
    const an = -i * (i - a);
    b += 2;
    d = an * d + b;
    if (Math.abs(d) < tiny) d = tiny;
    c = b + an / c;
    if (Math.abs(c) < tiny) c = tiny;
    d = 1 / d;
    const del = d * c;
    h *= del;
    if (Math.abs(del - 1) < 1e-15) break;
  }
  return Math.exp(-x + a * Math.log(x) - lnGamma(a)) * h;
}

// P(X >= x) for a chi-square variable with `df` degrees of freedom.
export const chiSquareP = (x, df) => gammaQ(df / 2, x / 2);

// Two-sided p-value of a standard normal statistic.
export const normalP = (z) => gammaQ(0.5, (z * z) / 2);

// Chi-square test of homogeneity: are two samples spread over the same
// categories in the same proportions? a and b are arrays of counts.
export function chiSquareTwoSample(a, b) {
  const totalA = a.reduce((s, v) => s + v, 0);
  const totalB = b.reduce((s, v) => s + v, 0);
  let statistic = 0;
  let categories = 0;
  for (let i = 0; i < a.length; i++) {
    const column = a[i] + b[i];
    if (column === 0) continue;
    categories += 1;
    const expectedA = (column * totalA) / (totalA + totalB);
    const expectedB = (column * totalB) / (totalA + totalB);
    statistic += (a[i] - expectedA) ** 2 / expectedA + (b[i] - expectedB) ** 2 / expectedB;
  }
  const df = Math.max(categories - 1, 1);
  return { statistic, df, p: chiSquareP(statistic, df) };
}

// Welch's z statistic for the difference of two means (large samples).
export function meanDifference(a, b) {
  const mean = (v) => v.reduce((s, x) => s + x, 0) / v.length;
  const variance = (v, m) => v.reduce((s, x) => s + (x - m) ** 2, 0) / (v.length - 1);
  const ma = mean(a);
  const mb = mean(b);
  const error = Math.sqrt(variance(a, ma) / a.length + variance(b, mb) / b.length);
  // Two constant samples: either identical or perfectly separated.
  if (error === 0) return { meanA: ma, meanB: mb, statistic: ma === mb ? 0 : Math.sign(ma - mb) * 1e9, p: ma === mb ? 1 : 0 };
  const z = (ma - mb) / error;
  return { meanA: ma, meanB: mb, statistic: z, p: normalP(z) };
}

// Two-sample Kolmogorov-Smirnov test on real-valued samples.
export function kolmogorovSmirnov(a, b) {
  const x = [...a].sort((p, q) => p - q);
  const y = [...b].sort((p, q) => p - q);
  let i = 0;
  let j = 0;
  let d = 0;
  while (i < x.length && j < y.length) {
    if (x[i] <= y[j]) i += 1;
    else j += 1;
    d = Math.max(d, Math.abs(i / x.length - j / y.length));
  }
  const effective = (x.length * y.length) / (x.length + y.length);
  const lambda = (Math.sqrt(effective) + 0.12 + 0.11 / Math.sqrt(effective)) * d;
  let p = 0;
  for (let k = 1; k <= 100; k++) p += 2 * (k % 2 ? 1 : -1) * Math.exp(-2 * k * k * lambda * lambda);
  return { statistic: d, p: Math.min(Math.max(p, 0), 1) };
}

// 95% Wilson interval for a proportion.
export function wilson(successes, n) {
  const z = 1.959964;
  const phat = successes / n;
  const denom = 1 + (z * z) / n;
  const centre = (phat + (z * z) / (2 * n)) / denom;
  const half = (z * Math.sqrt((phat * (1 - phat)) / n + (z * z) / (4 * n * n))) / denom;
  return { low: centre - half, high: centre + half };
}

// Probability of at least `hits` successes in `n` trials with success chance p.
export function binomialTail(hits, n, p) {
  let total = 0;
  for (let k = hits; k <= n; k++) {
    let choose = 1;
    for (let i = 0; i < k; i++) choose = (choose * (n - i)) / (i + 1);
    total += choose * p ** k * (1 - p) ** (n - k);
  }
  return total;
}
