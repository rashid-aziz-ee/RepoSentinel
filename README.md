# RepoSentinel — AI-Agent Firewall

## The Problem
AI coding agents are routinely given autonomy over real repositories. But every input is untrusted text from the internet. A single poisoned GitHub issue or booby-trapped README can trick an autonomous agent into leaking secrets or running destructive commands.

## What is RepoSentinel?
RepoSentinel sits between an AI agent and the repository, inspecting every untrusted input before the agent acts on it. It assigns a risk score and can Allow, Sanitize, Sandbox, or Block the agent's actions.

## Team Setup
- **Person A**: Detection Engine (Prompt-injection detection, risk scoring).
- **Person B**: Agent Interception Layer (Proxy/middleware).
- **Person C**: Backend + Dashboard.
- **Person D**: Secrets/Dependency Scanning + Demo/Pitch.
