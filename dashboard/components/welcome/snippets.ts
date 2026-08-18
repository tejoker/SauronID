// Code snippets shown on /welcome. Deliberately isolated in one file so the
// SDK workstream can replace them without touching the page component.
// ponytail: placeholder snippets — swap for finalized SDK code when ready.

export type SnippetLang = "python" | "typescript" | "go";

export const SNIPPET_LANGS: SnippetLang[] = ["python", "typescript", "go"];

export const LANG_LABELS: Record<SnippetLang, string> = {
  python: "Python",
  typescript: "TypeScript",
  go: "Go",
};

export const INSTALL_SNIPPETS: Record<SnippetLang, string> = {
  python: "pip install sauronid-client",
  typescript: "npm install @sauronid/agentic",
  go: "go get github.com/tejoker/SauronID/clients/go/sauronid",
};

export const REGISTER_SNIPPETS: Record<SnippetLang, string> = {
  python: `from sauronid_client import SauronClient

client = SauronClient(
    base_url="http://localhost:3001",
    api_key="YOUR_API_KEY",
)

# 1. Register an agent identity.
agent = client.register_agent(
    name="my-first-agent",
    agent_type="assistant",
    allowed_intents=["read:demo"],
)

# 2. Make a leashed call — signed, nonce-protected,
#    checked against your policy before it executes.
result = agent.call(
    intent="read:demo",
    action={"method": "GET", "url": "https://api.example.com/demo"},
)
print(result)`,
  typescript: `import { SauronClient } from "@sauronid/agentic";

const client = new SauronClient({
  baseUrl: "http://localhost:3001",
  apiKey: "YOUR_API_KEY",
});

// 1. Register an agent identity.
const agent = await client.registerAgent({
  name: "my-first-agent",
  agentType: "assistant",
  allowedIntents: ["read:demo"],
});

// 2. Make a leashed call — signed, nonce-protected,
//    checked against your policy before it executes.
const result = await agent.call({
  intent: "read:demo",
  action: { method: "GET", url: "https://api.example.com/demo" },
});
console.log(result);`,
  go: `package main

import (
    "fmt"

    sauronid "github.com/tejoker/SauronID/clients/go/sauronid"
)

func main() {
    client := sauronid.NewClient("http://localhost:3001", "YOUR_API_KEY")

    // 1. Register an agent identity.
    agent, err := client.RegisterAgent("my-first-agent", "assistant",
        []string{"read:demo"})
    if err != nil {
        panic(err)
    }

    // 2. Make a leashed call — signed, nonce-protected,
    //    checked against your policy before it executes.
    result, err := agent.Call("read:demo", map[string]any{
        "method": "GET",
        "url":    "https://api.example.com/demo",
    })
    if err != nil {
        panic(err)
    }
    fmt.Println(result)
}`,
};
