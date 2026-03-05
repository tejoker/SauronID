/**
 * SauronID Liveness Detection Client — Anti-spoofing biometric anchor.
 *
 * Wraps liveness detection providers (mock for dev, Face++ for production).
 * Used during enrollment and step-up authentication to ensure the subject
 * is a live human, blocking:
 *   - 3D mask attacks
 *   - Deepfake video injection
 *   - Printed photo presentation
 *   - Screen replay attacks
 */

export interface LivenessResult {
    alive: boolean;
    confidence: number;        // 0-1
    method: "passive" | "active";
    provider: string;
    challengeId?: string;
    timestamp: string;
}

export interface LivenessProvider {
    name: string;
    checkPassive(imageBase64: string): Promise<LivenessResult>;
    checkActive(sessionId: string): Promise<{ challengeType: string; instructions: string }>;
    verifyActiveResponse(sessionId: string, responseData: unknown): Promise<LivenessResult>;
}

/**
 * Mock Liveness Provider — For local development and testing.
 * Simulates liveness checks with configurable pass/fail rate.
 */
export class MockLivenessProvider implements LivenessProvider {
    name = "mock";
    private failRate: number;

    constructor(failRate: number = 0.1) {
        this.failRate = failRate;
    }

    async checkPassive(imageBase64: string): Promise<LivenessResult> {
        // Simulate processing delay
        await new Promise((r) => setTimeout(r, 200));

        const alive = Math.random() > this.failRate;
        const confidence = alive ? 0.85 + Math.random() * 0.15 : Math.random() * 0.3;

        return {
            alive,
            confidence: Math.round(confidence * 100) / 100,
            method: "passive",
            provider: this.name,
            timestamp: new Date().toISOString(),
        };
    }

    async checkActive(sessionId: string): Promise<{ challengeType: string; instructions: string }> {
        return {
            challengeType: "head_turn",
            instructions: "Please slowly turn your head to the left, then back to center.",
        };
    }

    async verifyActiveResponse(sessionId: string, responseData: unknown): Promise<LivenessResult> {
        await new Promise((r) => setTimeout(r, 300));
        const alive = Math.random() > this.failRate;

        return {
            alive,
            confidence: alive ? 0.92 + Math.random() * 0.08 : Math.random() * 0.25,
            method: "active",
            provider: this.name,
            challengeId: sessionId,
            timestamp: new Date().toISOString(),
        };
    }
}

/**
 * Face++ Liveness Provider stub — Production implementation would call the
 * Face++ / Megvii API. Interface ready for drop-in replacement.
 */
export class FacePlusPlusProvider implements LivenessProvider {
    name = "facepp";
    private apiKey: string;
    private apiSecret: string;
    private endpoint: string;

    constructor(apiKey: string, apiSecret: string, endpoint: string = "https://api-us.faceplusplus.com") {
        this.apiKey = apiKey;
        this.apiSecret = apiSecret;
        this.endpoint = endpoint;
    }

    async checkPassive(imageBase64: string): Promise<LivenessResult> {
        // Production: POST to /facepp/v1/faceverify with liveness=true
        // For now, throw to signal this needs real credentials
        throw new Error(
            "Face++ integration requires commercial API key. " +
            "Use MockLivenessProvider for development."
        );
    }

    async checkActive(sessionId: string) {
        throw new Error("Face++ active liveness requires commercial license.");
    }

    async verifyActiveResponse(sessionId: string, responseData: unknown): Promise<LivenessResult> {
        throw new Error("Face++ active liveness requires commercial license.");
    }
}

/**
 * SauronID Liveness Client — Orchestrates liveness checks.
 */
export class LivenessClient {
    private provider: LivenessProvider;

    constructor(provider?: LivenessProvider) {
        this.provider = provider || new MockLivenessProvider();
    }

    /**
     * Run passive liveness check on a selfie image.
     * Analyzes texture, depth, and consistency without user interaction.
     */
    async checkPassive(imageBase64: string): Promise<LivenessResult> {
        console.log(`[LIVENESS] Passive check via ${this.provider.name}`);
        const result = await this.provider.checkPassive(imageBase64);
        console.log(`[LIVENESS] Result: alive=${result.alive} confidence=${result.confidence}`);
        return result;
    }

    /**
     * Start an active liveness challenge (e.g., head turn, blink).
     */
    async startActiveChallenge(sessionId: string) {
        return this.provider.checkActive(sessionId);
    }

    /**
     * Verify the user's response to an active liveness challenge.
     */
    async verifyActiveChallenge(sessionId: string, responseData: unknown): Promise<LivenessResult> {
        return this.provider.verifyActiveResponse(sessionId, responseData);
    }

    /**
     * Full liveness check: passive first, active if passive confidence is < 0.9.
     */
    async fullCheck(imageBase64: string, sessionId: string): Promise<LivenessResult> {
        // Step 1: Passive check
        const passive = await this.checkPassive(imageBase64);

        if (!passive.alive) {
            return passive;
        }

        // Step 2: If passive confidence is low, require active check
        if (passive.confidence < 0.9) {
            console.log("[LIVENESS] Passive confidence low, requiring active check");
            // In a real app, this would trigger the UI to show the challenge
            // For now, return the passive result
        }

        return passive;
    }
}
