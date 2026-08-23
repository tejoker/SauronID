/**
 * SauronID Workflow Tracker — Monitors agent execution against authorized workflows.
 *
 * Tracks the sequence of actions an agent performs and validates them against
 * a pre-defined workflow graph. If the agent deviates from the expected flow
 * (e.g., due to prompt injection), the tracker flags the violation and can
 * trigger an automated threat response.
 *
 * Telemetry events emitted by this tracker feed into the Anomaly Detection Engine.
 */

export interface WorkflowStep {
    /** Unique step identifier */
    id: string;
    /** Human-readable step name */
    name: string;
    /** List of allowed next step IDs */
    allowedNext: string[];
    /** Maximum duration for this step (ms) */
    maxDurationMs?: number;
    /** Whether this is a terminal state */
    terminal?: boolean;
}

export interface WorkflowDefinition {
    /** Workflow identifier */
    id: string;
    /** Human-readable name */
    name: string;
    /** The starting step ID */
    entryPoint: string;
    /** All steps in the workflow */
    steps: Map<string, WorkflowStep>;
}

export interface StepExecution {
    stepId: string;
    startedAt: number;
    completedAt?: number;
    result?: "success" | "failure" | "skipped";
    metadata?: Record<string, unknown>;
}

export interface WorkflowViolation {
    type: "unauthorized_step" | "sequence_violation" | "timeout" | "unknown_step";
    message: string;
    attemptedStep: string;
    currentStep: string;
    timestamp: string;
}

export type TelemetryEvent = {
    type: "step_started" | "step_completed" | "violation" | "workflow_completed";
    workflowId: string;
    stepId: string;
    timestamp: string;
    details: Record<string, unknown>;
};

/**
 * WorkflowTracker — Validates agent behavior against a workflow graph.
 */
export class WorkflowTracker {
    private definition: WorkflowDefinition;
    private currentStepId: string;
    private executionLog: StepExecution[] = [];
    private violations: WorkflowViolation[] = [];
    private telemetryBuffer: TelemetryEvent[] = [];
    private startedAt: number;
    private stepStartedAt: number;

    constructor(definition: WorkflowDefinition) {
        this.definition = definition;
        this.currentStepId = definition.entryPoint;
        this.startedAt = Date.now();
        this.stepStartedAt = Date.now();

        this.emitTelemetry("step_started", definition.entryPoint, {});
    }

    /**
     * Check if a step transition is allowed BEFORE executing it.
     */
    isAllowed(nextStepId: string): boolean {
        const currentStep = this.definition.steps.get(this.currentStepId);
        if (!currentStep) return false;
        if (currentStep.terminal) return false;
        return currentStep.allowedNext.includes(nextStepId);
    }

    /**
     * Record that the agent is starting a new step.
     * Returns true if the transition is valid, false if it's a violation.
     */
    recordStep(stepId: string, metadata?: Record<string, unknown>): boolean {
        const currentStep = this.definition.steps.get(this.currentStepId);
        const now = Date.now();

        // Check if the step exists in the workflow
        if (!this.definition.steps.has(stepId)) {
            this.addViolation("unknown_step", stepId, `Step '${stepId}' not in workflow definition`);
            return false;
        }

        // Check if the transition is allowed
        if (currentStep && !currentStep.allowedNext.includes(stepId)) {
            this.addViolation(
                "sequence_violation",
                stepId,
                `Transition ${this.currentStepId} → ${stepId} not allowed. Allowed: [${currentStep.allowedNext.join(", ")}]`
            );
            return false;
        }

        // Check timeout on current step
        if (currentStep?.maxDurationMs) {
            const elapsed = now - this.stepStartedAt;
            if (elapsed > currentStep.maxDurationMs) {
                this.addViolation(
                    "timeout",
                    stepId,
                    `Step '${this.currentStepId}' exceeded max duration: ${elapsed}ms > ${currentStep.maxDurationMs}ms`
                );
            }
        }

        // Complete previous step
        if (this.executionLog.length > 0) {
            const prevExec = this.executionLog[this.executionLog.length - 1];
            prevExec.completedAt = now;
            prevExec.result = "success";
            this.emitTelemetry("step_completed", this.currentStepId, {
                duration: now - this.stepStartedAt,
            });
        }

        // Start new step
        this.currentStepId = stepId;
        this.stepStartedAt = now;
        this.executionLog.push({
            stepId,
            startedAt: now,
            metadata,
        });

        this.emitTelemetry("step_started", stepId, metadata || {});

        // Check if this completes the workflow
        const newStep = this.definition.steps.get(stepId);
        if (newStep?.terminal) {
            this.emitTelemetry("workflow_completed", stepId, {
                totalDuration: now - this.startedAt,
                totalSteps: this.executionLog.length,
                violations: this.violations.length,
            });
        }

        return true;
    }

    /**
     * Get the current workflow state.
     */
    getState(): {
        workflowId: string;
        currentStep: string;
        stepsCompleted: number;
        violations: WorkflowViolation[];
        isComplete: boolean;
        duration: number;
    } {
        const currentStep = this.definition.steps.get(this.currentStepId);
        return {
            workflowId: this.definition.id,
            currentStep: this.currentStepId,
            stepsCompleted: this.executionLog.length,
            violations: [...this.violations],
            isComplete: currentStep?.terminal || false,
            duration: Date.now() - this.startedAt,
        };
    }

    /**
     * Flush telemetry events (consumed by the anomaly engine).
     */
    flushTelemetry(): TelemetryEvent[] {
        const events = [...this.telemetryBuffer];
        this.telemetryBuffer = [];
        return events;
    }

    /**
     * Get all violations recorded so far.
     */
    getViolations(): WorkflowViolation[] {
        return [...this.violations];
    }

    private addViolation(
        type: WorkflowViolation["type"],
        attemptedStep: string,
        message: string
    ) {
        const violation: WorkflowViolation = {
            type,
            message,
            attemptedStep,
            currentStep: this.currentStepId,
            timestamp: new Date().toISOString(),
        };
        this.violations.push(violation);
        this.emitTelemetry("violation", attemptedStep, { violation });
    }

    private emitTelemetry(
        type: TelemetryEvent["type"],
        stepId: string,
        details: Record<string, unknown>
    ) {
        this.telemetryBuffer.push({
            type,
            workflowId: this.definition.id,
            stepId,
            timestamp: new Date().toISOString(),
            details,
        });
    }
}

/**
 * Helper to build a WorkflowDefinition from a simple graph description.
 */
export function buildWorkflow(
    id: string,
    name: string,
    entryPoint: string,
    steps: Array<{
        id: string;
        name: string;
        next: string[];
        maxDurationMs?: number;
        terminal?: boolean;
    }>
): WorkflowDefinition {
    const stepMap = new Map<string, WorkflowStep>();
    for (const step of steps) {
        stepMap.set(step.id, {
            id: step.id,
            name: step.name,
            allowedNext: step.next,
            maxDurationMs: step.maxDurationMs,
            terminal: step.terminal,
        });
    }
    return { id, name, entryPoint, steps: stepMap };
}
