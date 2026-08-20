import { ChildProcess, spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { ProofArtifactOptions, PrivaPurchaseAuthInputs, PrivaPurchaseAuthProofPayload, ZkAuthProofInputs, ZkAuthProofPayload } from '../sdk/types.js';

export type AuthenticateProverJob = {
  kind: 'authenticate';
  inputs: ZkAuthProofInputs;
  artifactOpts?: ProofArtifactOptions;
};

export type PrivaProverJob = {
  kind: 'priva';
  inputs: PrivaPurchaseAuthInputs;
};

export type ProverJob = AuthenticateProverJob | PrivaProverJob;

export interface ProverPoolOptions {
  maxWorkers: number;
  maxQueueDepth: number;
  jobTimeoutMs: number;
}

interface PendingJob {
  id: number;
  job: ProverJob;
  resolve: (value: ZkAuthProofPayload | PrivaPurchaseAuthProofPayload) => void;
  reject: (error: Error) => void;
  timer?: NodeJS.Timeout;
}

interface WorkerSlot {
  worker: ChildProcess;
  current?: PendingJob;
}

/**
 * Bounded worker-thread prover pool. Proof generation is deliberately kept out
 * of the HTTP event loop; queue admission and per-job timeouts are enforced at
 * both the gateway and worker boundary.
 */
export class ProverPool {
  private readonly options: ProverPoolOptions;
  private readonly slots: WorkerSlot[] = [];
  private readonly queue: PendingJob[] = [];
  private nextJobId = 1;
  private closed = false;

  constructor(options: ProverPoolOptions) {
    if (!Number.isSafeInteger(options.maxWorkers) || options.maxWorkers < 1) throw new Error('maxWorkers must be a positive integer');
    if (!Number.isSafeInteger(options.maxQueueDepth) || options.maxQueueDepth < 0) throw new Error('maxQueueDepth must be a non-negative integer');
    if (!Number.isSafeInteger(options.jobTimeoutMs) || options.jobTimeoutMs < 1000) throw new Error('jobTimeoutMs must be an integer >= 1000');
    this.options = options;
  }

  get activeJobs(): number { return this.slots.filter((slot) => slot.current !== undefined).length; }
  get queuedJobs(): number { return this.queue.length; }
  get workerCount(): number { return this.slots.length; }

  run(job: AuthenticateProverJob): Promise<ZkAuthProofPayload>;
  run(job: PrivaProverJob): Promise<PrivaPurchaseAuthProofPayload>;
  run(job: ProverJob): Promise<ZkAuthProofPayload | PrivaPurchaseAuthProofPayload> {
    if (this.closed) return Promise.reject(new Error('prover pool is closed'));
    if (this.queue.length >= this.options.maxQueueDepth && this.slots.every((slot) => slot.current !== undefined) && this.slots.length >= this.options.maxWorkers) {
      return Promise.reject(new Error('prover busy; retry later'));
    }
    return new Promise((resolve, reject) => {
      this.queue.push({ id: this.nextJobId++, job, resolve, reject });
      this.dispatch();
    });
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    const error = new Error('prover pool is closed');
    for (const pending of this.queue.splice(0)) pending.reject(error);
    const terminations = this.slots.splice(0).map((slot) => {
      if (slot.current) {
        if (slot.current.timer) clearTimeout(slot.current.timer);
        slot.current.reject(error);
      }
      return new Promise<void>((resolve) => {
        slot.worker.once('exit', () => resolve());
        slot.worker.kill();
      });
    });
    await Promise.allSettled(terminations);
  }

  private dispatch(): void {
    if (this.closed) return;
    while (this.queue.length) {
      let slot = this.slots.find((candidate) => candidate.current === undefined);
      if (!slot && this.slots.length < this.options.maxWorkers) {
        slot = this.createSlot();
      }
      if (!slot) return;
      const pending = this.queue.shift()!;
      slot.current = pending;
      pending.timer = setTimeout(() => this.failTimedOut(slot!, pending), this.options.jobTimeoutMs);
      slot.worker.send?.({ jobId: pending.id, ...pending.job, artifactOpts: pending.job.kind === 'authenticate' ? (pending.job.artifactOpts ?? {}) : undefined });
    }
  }

  private createSlot(): WorkerSlot {
    const workerPath = fileURLToPath(new URL('./prover-worker.js', import.meta.url));
    const slot: WorkerSlot = {
      worker: spawn(process.execPath, [workerPath], { stdio: ['ignore', 'ignore', 'ignore', 'ipc'] }),
    };
    slot.worker.unref();
    slot.worker.on('message', (message: { jobId: number; ok: boolean; result?: ZkAuthProofPayload | PrivaPurchaseAuthProofPayload; error?: string }) => {
      const pending = slot.current;
      if (!pending || pending.id !== message.jobId) return;
      if (pending.timer) clearTimeout(pending.timer);
      slot.current = undefined;
      if (message.ok && message.result) pending.resolve(message.result);
      else pending.reject(new Error(message.error || 'proof generation failed'));
      this.dispatch();
    });
    slot.worker.on('error', (error) => {
      const pending = slot.current;
      if (pending) {
        if (pending.timer) clearTimeout(pending.timer);
        slot.current = undefined;
        pending.reject(new Error(`prover worker failed: ${error instanceof Error ? error.message : 'unknown worker error'}`));
      }
      this.removeSlot(slot);
      this.dispatch();
    });
    slot.worker.on('exit', (code) => {
      const pending = slot.current;
      if (pending) {
        if (pending.timer) clearTimeout(pending.timer);
        slot.current = undefined;
        pending.reject(new Error(`prover worker exited with code ${code}`));
      }
      this.removeSlot(slot);
      this.dispatch();
    });
    this.slots.push(slot);
    return slot;
  }

  private failTimedOut(slot: WorkerSlot, pending: PendingJob): void {
    if (slot.current !== pending) return;
    slot.current = undefined;
    pending.reject(new Error('proof generation timed out'));
    this.removeSlot(slot);
    slot.worker.kill();
    this.dispatch();
  }

  private removeSlot(slot: WorkerSlot): void {
    const index = this.slots.indexOf(slot);
    if (index >= 0) this.slots.splice(index, 1);
  }
}
