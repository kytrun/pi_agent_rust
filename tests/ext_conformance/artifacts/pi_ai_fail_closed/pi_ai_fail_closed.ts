import {
    complete,
    completeSimple,
    getApiProvider,
    getEnvApiKey,
    getModel,
    getModels,
    getOAuthApiKey,
    loginOpenAICodex,
    refreshOpenAICodexToken,
    streamSimpleAnthropic,
    streamSimpleOpenAICompletions,
    streamSimpleOpenAIResponses,
} from "@mariozechner/pi-ai";
import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";

const unsupportedChecks: Array<[string, () => unknown]> = [
    ["complete", () => complete({})],
    ["completeSimple", () => completeSimple("prompt")],
    ["streamSimpleAnthropic", () => consumeStream(streamSimpleAnthropic("model", "prompt"))],
    [
        "streamSimpleOpenAIResponses",
        () => consumeStream(streamSimpleOpenAIResponses("model", "prompt")),
    ],
    [
        "streamSimpleOpenAICompletions",
        () => consumeStream(streamSimpleOpenAICompletions("model", "prompt")),
    ],
    ["getModel", () => getModel()],
    ["getApiProvider", () => getApiProvider()],
    ["getModels", () => getModels()],
    ["loginOpenAICodex", () => loginOpenAICodex()],
    ["refreshOpenAICodexToken", () => refreshOpenAICodexToken()],
    ["getOAuthApiKey", () => getOAuthApiKey("openai")],
];

async function consumeStream(stream: AsyncIterable<unknown>): Promise<void> {
    for await (const _ of stream) {
        // The host bridge must fail before yielding placeholder chunks.
    }
}

async function expectFailClosed(name: string, call: () => unknown): Promise<string> {
    try {
        await call();
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (message.includes(name) && message.includes("refusing to return placeholder data")) {
            return `${name}:fail-closed`;
        }
        return `${name}:wrong-error:${message}`;
    }
    return `${name}:unexpected-success`;
}

export default function(pi: ExtensionAPI) {
    pi.registerTool({
        name: "pi_ai_contract",
        description: "Verifies @mariozechner/pi-ai unsupported helpers fail closed.",
        parameters: {
            type: "object",
            properties: {},
            additionalProperties: false,
        },
        execute: async () => {
            const lines = [
                `getEnvApiKey:export:${typeof getEnvApiKey}`,
                `getOAuthApiKey:export:${typeof getOAuthApiKey}`,
            ];

            for (const [name, call] of unsupportedChecks) {
                lines.push(await expectFailClosed(name, call));
            }

            return {
                content: [{ type: "text", text: lines.join("\n") }],
            };
        },
    });
}
