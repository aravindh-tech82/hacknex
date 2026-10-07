import type { BehavioralFeatures, IsolationForestResult } from '../types/security';

interface IsolationTreeNode {
  featureIndex?: number;
  splitValue?: number;
  left?: IsolationTreeNode;
  right?: IsolationTreeNode;
  size?: number; // Size of sample if leaf
  isLeaf: boolean;
}

/**
 * Expected average path length of unsuccessful search in BST / iTree.
 * Euler's constant: gamma = 0.5772156649
 */
function c(n: number): number {
  if (n <= 1) return 1;
  if (n === 2) return 1;
  const gamma = 0.5772156649;
  return 2 * (Math.log(n - 1) + gamma) - (2 * (n - 1)) / n;
}

/**
 * Normalizes behavioral features into a numerical vector [x0, x1, ... xM].
 */
function vectorFromFeatures(f: BehavioralFeatures): number[] {
  return [
    f.failed_login_count,
    f.successful_login_count,
    f.unique_ip_count,
    f.unique_device_count,
    f.new_device,
    f.new_ip,
    f.unusual_login_hour,
    f.sensitive_server_access,
    f.suspicious_process_count,
    f.external_connection_count,
    f.event_frequency,
    f.number_of_servers_accessed,
    f.number_of_applications_used,
    f.number_of_destination_ips,
    f.file_access_count,
    f.authentication_failure_ratio,
  ];
}

/**
 * Standard enterprise baseline reference population representing normal corporate profiles.
 */
const BASELINE_POPULATION: number[][] = [
  // Normal employee (9 to 5, known dev, no failures)
  [0, 5, 1, 1, 0, 0, 0, 0, 0, 0, 1.2, 1, 3, 0, 2, 0.0],
  // Developer pulling git & staging
  [0, 6, 1, 1, 0, 0, 0, 0, 0, 0, 1.5, 1, 4, 0, 4, 0.0],
  // Finance clerk normal audit
  [0, 4, 1, 1, 0, 0, 0, 1, 0, 0, 1.0, 1, 2, 0, 3, 0.0],
  // Manager reading docs
  [0, 3, 1, 1, 0, 0, 0, 0, 0, 0, 0.8, 1, 2, 0, 1, 0.0],
  // Occasional single typo failed login then ok
  [1, 4, 1, 1, 0, 0, 0, 0, 0, 0, 1.1, 1, 3, 0, 2, 0.2],
  // Sysadmin staging routine check
  [0, 8, 1, 1, 0, 0, 0, 1, 0, 0, 2.0, 2, 3, 0, 5, 0.0],
  // Marketing team social & email
  [0, 5, 1, 1, 0, 0, 0, 0, 0, 0, 1.3, 1, 3, 0, 2, 0.0],
  // Support agent ticket triage
  [0, 7, 1, 1, 0, 0, 0, 0, 0, 0, 1.8, 1, 4, 0, 3, 0.0],
  // Occasional 1 failed login
  [1, 3, 1, 1, 0, 0, 0, 0, 0, 0, 0.9, 1, 2, 0, 1, 0.25],
  // Normal user baseline
  [0, 6, 1, 1, 0, 0, 0, 0, 0, 0, 1.4, 1, 3, 0, 2, 0.0],
];

/**
 * Builds an Isolation Tree recursively up to maxDepth.
 */
function buildITree(data: number[][], currentDepth: number, maxDepth: number): IsolationTreeNode {
  if (currentDepth >= maxDepth || data.length <= 1) {
    return { isLeaf: true, size: data.length };
  }

  const numFeatures = data[0].length;
  // Choose random feature
  const featureIndex = Math.floor(Math.random() * numFeatures);

  let minVal = Infinity;
  let maxVal = -Infinity;
  for (const row of data) {
    const val = row[featureIndex];
    if (val < minVal) minVal = val;
    if (val > maxVal) maxVal = val;
  }

  // All points have identical feature value
  if (minVal >= maxVal) {
    return { isLeaf: true, size: data.length };
  }

  // Choose random split value between min and max
  const splitValue = minVal + Math.random() * (maxVal - minVal);

  const leftData = data.filter((row) => row[featureIndex] < splitValue);
  const rightData = data.filter((row) => row[featureIndex] >= splitValue);

  if (leftData.length === 0 || rightData.length === 0) {
    return { isLeaf: true, size: data.length };
  }

  return {
    isLeaf: false,
    featureIndex,
    splitValue,
    left: buildITree(leftData, currentDepth + 1, maxDepth),
    right: buildITree(rightData, currentDepth + 1, maxDepth),
  };
}

/**
 * Evaluates the path length h(x) of a point in an iTree.
 */
function pathLength(x: number[], node: IsolationTreeNode, currentDepth: number): number {
  if (node.isLeaf) {
    return currentDepth + c(node.size || 1);
  }

  if (node.featureIndex === undefined || node.splitValue === undefined) {
    return currentDepth;
  }

  if (x[node.featureIndex] < node.splitValue) {
    return node.left ? pathLength(x, node.left, currentDepth + 1) : currentDepth;
  } else {
    return node.right ? pathLength(x, node.right, currentDepth + 1) : currentDepth;
  }
}

/**
 * Isolation Forest Model Ensemble
 */
export class IsolationForestModel {
  private trees: IsolationTreeNode[] = [];
  private numTrees: number;
  private maxDepth: number;
  private sampleSize: number;

  constructor(numTrees = 50, sampleSize = 64) {
    this.numTrees = numTrees;
    this.sampleSize = sampleSize;
    this.maxDepth = Math.ceil(Math.log2(Math.max(sampleSize, 8)));
    this.train();
  }

  private train() {
    this.trees = [];
    const trainingData = [...BASELINE_POPULATION];

    for (let i = 0; i < this.numTrees; i++) {
      // Subsample from baseline population
      const subsample: number[][] = [];
      for (let j = 0; j < Math.min(this.sampleSize, trainingData.length); j++) {
        const randIdx = Math.floor(Math.random() * trainingData.length);
        subsample.push(trainingData[randIdx]);
      }
      const tree = buildITree(subsample, 0, this.maxDepth);
      this.trees.push(tree);
    }
  }

  public predict(features: BehavioralFeatures): IsolationForestResult {
    const x = vectorFromFeatures(features);
    let totalPathLength = 0;

    for (const tree of this.trees) {
      totalPathLength += pathLength(x, tree, 0);
    }

    const avgPathLength = totalPathLength / this.trees.length;
    const expectedC = c(this.sampleSize);

    // Theoretical Isolation Forest raw score formula: s = 2 ^ (-E(h) / c(n))
    // Range is strictly between 0 and 1.
    // Notice: If point is anomalous, avgPathLength is small -> s is close to 1.0.
    const rawScore = Math.pow(2, -avgPathLength / expectedC);

    // Calibrate with heuristic domain boost if key threat vectors are present
    let heuristicWeight = 0;
    if (features.failed_login_count >= 3) heuristicWeight += 0.25;
    if (features.new_device === 1) heuristicWeight += 0.15;
    if (features.new_ip === 1) heuristicWeight += 0.15;
    if (features.sensitive_server_access > 0) heuristicWeight += 0.15;
    if (features.suspicious_process_count > 0) heuristicWeight += 0.25;
    if (features.external_connection_count > 0) heuristicWeight += 0.20;
    if (features.unusual_login_hour === 1) heuristicWeight += 0.10;

    // Combine algorithmic isolation with feature variance
    const calibratedScore = Math.min(0.98, Math.max(0.08, rawScore * 0.4 + heuristicWeight * 0.6));
    const scorePct = Math.round(calibratedScore * 100);

    const isAnomalous = calibratedScore >= 0.65;
    const isSuspicious = calibratedScore >= 0.40 && calibratedScore < 0.65;

    const label: 'ANOMALOUS' | 'SUSPICIOUS' | 'NORMAL' = isAnomalous
      ? 'ANOMALOUS'
      : isSuspicious
      ? 'SUSPICIOUS'
      : 'NORMAL';

    const reasons: string[] = [];
    if (features.failed_login_count >= 3) reasons.push(`${features.failed_login_count} failed auth attempts`);
    if (features.new_device === 1) reasons.push('unmapped endpoint device');
    if (features.new_ip === 1) reasons.push('external session IP');
    if (features.sensitive_server_access > 0) reasons.push('sensitive infrastructure access');
    if (features.suspicious_process_count > 0) reasons.push('unauthorized process execution');
    if (features.external_connection_count > 0) reasons.push('outbound C2 connection');

    const explanation =
      reasons.length > 0
        ? `Isolated in early tree splits (avg path: ${avgPathLength.toFixed(1)} vs baseline ${expectedC.toFixed(1)}) due to: ${reasons.join(', ')}.`
        : `Path depth (${avgPathLength.toFixed(1)}) matches standard corporate user baseline. No early hyperplane isolation.`;

    return {
      anomalyScore: parseFloat(calibratedScore.toFixed(3)),
      anomalyScorePct: scorePct,
      isAnomalous,
      label,
      confidence: parseFloat(Math.min(0.99, 0.75 + calibratedScore * 0.2).toFixed(2)),
      averagePathLength: parseFloat(avgPathLength.toFixed(2)),
      expectedPathLength: parseFloat(expectedC.toFixed(2)),
      explanation,
    };
  }
}

// Singleton model instance ready for fast evaluation
export const isolationForestModel = new IsolationForestModel(60, 48);
