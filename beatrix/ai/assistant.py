"""
BEATRIX AI Assistant Module

Haiku = Marine Infantry 🎖️
- Fast, efficient, tireless
- Handles bulk recon and parsing
- First boots on the ground

Opus/Sonnet = Special Operations 🎯
- Complex vulnerability analysis
- Exploit chain development
- Strategic planning
"""

import asyncio
import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False


class AIProvider(Enum):
    """Supported AI providers"""
    ANTHROPIC = "anthropic"
    BEDROCK = "bedrock"
    OPENAI = "openai"  # For compatible endpoints


@dataclass
class AIConfig:
    """AI configuration"""
    provider: AIProvider = AIProvider.ANTHROPIC
    api_key: Optional[str] = None
    model: str = "claude-3-5-haiku-20241022"
    max_tokens: int = 4096
    temperature: float = 0.3

    # Bedrock specific
    aws_region: str = "us-east-1"
    aws_access_key: Optional[str] = None
    aws_secret_key: Optional[str] = None
    aws_session_token: Optional[str] = None

    # Rate limiting
    requests_per_minute: int = 60

    def __post_init__(self):
        # Try to load from environment
        if not self.api_key:
            self.api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not self.aws_access_key:
            self.aws_access_key = os.environ.get("AWS_ACCESS_KEY_ID")
        if not self.aws_secret_key:
            self.aws_secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
        if not self.aws_session_token:
            self.aws_session_token = os.environ.get("AWS_SESSION_TOKEN")


@dataclass
class AIMessage:
    """AI conversation message"""
    role: str  # "user", "assistant", "system"
    content: str


@dataclass
class AIResponse:
    """AI response wrapper"""
    content: str
    model: str
    usage: Dict[str, int] = field(default_factory=dict)
    raw_response: Optional[Dict] = None


class AIBackend(ABC):
    """Abstract AI backend"""

    @abstractmethod
    async def complete(self,
                      messages: List[AIMessage],
                      system: Optional[str] = None) -> AIResponse:
        pass


class AnthropicBackend(AIBackend):
    """Direct Anthropic API backend"""

    API_URL = "https://api.anthropic.com/v1/messages"

    def __init__(self, config: AIConfig):
        self.config = config
        if not HAS_HTTPX:
            raise ImportError("httpx required for Anthropic backend")

    async def complete(self,
                      messages: List[AIMessage],
                      system: Optional[str] = None) -> AIResponse:

        headers = {
            "x-api-key": self.config.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        # Convert messages to Anthropic format
        api_messages = []
        for msg in messages:
            if msg.role != "system":
                api_messages.append({
                    "role": msg.role,
                    "content": msg.content
                })

        payload = {
            "model": self.config.model,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
            "messages": api_messages,
        }

        if system:
            payload["system"] = system

        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.post(
                self.API_URL,
                headers=headers,
                json=payload
            )
            response.raise_for_status()
            data = response.json()

        return AIResponse(
            content=data["content"][0]["text"],
            model=data["model"],
            usage={
                "input_tokens": data["usage"]["input_tokens"],
                "output_tokens": data["usage"]["output_tokens"],
            },
            raw_response=data
        )


class BedrockBackend(AIBackend):
    """AWS Bedrock backend"""

    def __init__(self, config: AIConfig):
        self.config = config
        try:
            import boto3
            self.boto3 = boto3
        except ImportError:
            raise ImportError("boto3 required for Bedrock backend: pip install boto3")

        client_kwargs = {
            "region_name": config.aws_region,
        }
        # Only pass explicit credentials if provided (otherwise boto3
        # falls back to its standard credential chain: env vars,
        # ~/.aws/credentials, instance profile, etc.)
        if config.aws_access_key:
            client_kwargs["aws_access_key_id"] = config.aws_access_key
        if config.aws_secret_key:
            client_kwargs["aws_secret_access_key"] = config.aws_secret_key
        if config.aws_session_token:
            client_kwargs["aws_session_token"] = config.aws_session_token

        self.client = boto3.client("bedrock-runtime", **client_kwargs)

        # Map model names to Bedrock inference profile IDs.
        # Claude 4+ models REQUIRE inference profiles (on-demand model IDs
        # are rejected with ValidationException).  Older models also have
        # inference profiles and using them is the forward-compatible path.
        self.model_map = {
            # Claude 3
            "claude-3-haiku-20240307": "us.anthropic.claude-3-haiku-20240307-v1:0",
            "claude-3-sonnet-20240229": "us.anthropic.claude-3-sonnet-20240229-v1:0",
            "claude-3-opus-20240229": "us.anthropic.claude-3-opus-20240229-v1:0",
            # Claude 3.5
            "claude-3-5-sonnet-20240620": "us.anthropic.claude-3-5-sonnet-20240620-v1:0",
            "claude-3-5-sonnet-20241022": "us.anthropic.claude-3-5-sonnet-20241022-v2:0",
            "claude-3-5-haiku-20241022": "us.anthropic.claude-3-5-haiku-20241022-v1:0",
            # Claude 3.7
            "claude-3-7-sonnet-20250219": "us.anthropic.claude-3-7-sonnet-20250219-v1:0",
            # Claude 4
            "claude-sonnet-4-20250514": "us.anthropic.claude-sonnet-4-20250514-v1:0",
            "claude-opus-4-20250514": "us.anthropic.claude-opus-4-20250514-v1:0",
            "claude-opus-4-1-20250805": "us.anthropic.claude-opus-4-1-20250805-v1:0",
            # Claude 4.5
            "claude-haiku-4-5-20251001": "us.anthropic.claude-haiku-4-5-20251001-v1:0",
            "claude-sonnet-4-5-20250929": "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
            "claude-opus-4-5-20251101": "us.anthropic.claude-opus-4-5-20251101-v1:0",
            # Claude 4.6
            "claude-opus-4-6": "us.anthropic.claude-opus-4-6-v1",
            "claude-sonnet-4-6": "us.anthropic.claude-sonnet-4-6",
        }

    async def complete(self,
                      messages: List[AIMessage],
                      system: Optional[str] = None) -> AIResponse:

        # Convert to Bedrock format
        api_messages = []
        for msg in messages:
            if msg.role != "system":
                api_messages.append({
                    "role": msg.role,
                    "content": [{"type": "text", "text": msg.content}]
                })

        model_id = self.model_map.get(self.config.model, self.config.model)

        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
            "messages": api_messages,
        }

        if system:
            body["system"] = system

        # Run in executor to not block
        loop = asyncio.get_running_loop()
        response = await loop.run_in_executor(
            None,
            lambda: self.client.invoke_model(
                modelId=model_id,
                body=json.dumps(body)
            )
        )

        data = json.loads(response["body"].read())

        return AIResponse(
            content=data["content"][0]["text"],
            model=model_id,
            usage={
                "input_tokens": data["usage"]["input_tokens"],
                "output_tokens": data["usage"]["output_tokens"],
            },
            raw_response=data
        )


class AIAssistant:
    """
    Main AI Assistant class.

    Handles communication with AI backends and manages conversations.
    """

    def __init__(self, config: Optional[AIConfig] = None):
        self.config = config or AIConfig()
        self.backend = self._create_backend()
        self.conversation: List[AIMessage] = []
        self.system_prompt: Optional[str] = None
        self.total_tokens_used = 0

    def _create_backend(self) -> AIBackend:
        """Create appropriate backend based on config"""
        if self.config.provider == AIProvider.ANTHROPIC:
            return AnthropicBackend(self.config)
        elif self.config.provider == AIProvider.BEDROCK:
            return BedrockBackend(self.config)
        else:
            raise ValueError(f"Unsupported provider: {self.config.provider}")

    def set_system_prompt(self, prompt: str):
        """Set the system prompt for all conversations"""
        self.system_prompt = prompt

    def clear_conversation(self):
        """Clear conversation history"""
        self.conversation = []

    async def chat(self, message: str) -> str:
        """Send a message and get a response"""
        self.conversation.append(AIMessage(role="user", content=message))

        response = await self.backend.complete(
            self.conversation,
            system=self.system_prompt
        )

        self.conversation.append(AIMessage(role="assistant", content=response.content))
        self.total_tokens_used += response.usage.get("input_tokens", 0)
        self.total_tokens_used += response.usage.get("output_tokens", 0)

        return response.content

    async def complete(self, prompt: str, system: Optional[str] = None) -> str:
        """One-shot completion without conversation history"""
        messages = [AIMessage(role="user", content=prompt)]
        response = await self.backend.complete(messages, system=system or self.system_prompt)

        self.total_tokens_used += response.usage.get("input_tokens", 0)
        self.total_tokens_used += response.usage.get("output_tokens", 0)

        return response.content


class HaikuGrunt(AIAssistant):
    """
    Haiku-powered grunt worker for bulk tasks.

    🎖️ MARINE INFANTRY REPORTING FOR DUTY! 🎖️

    Specializations:
    - Bulk response analysis
    - Pattern matching in large datasets
    - Preliminary recon parsing
    - Data extraction and formatting
    - Repetitive analysis tasks

    Fast, efficient, tireless. First boots on the ground.
    """

    # Specialized system prompts for different tasks
    RECON_PROMPT = """You are a security reconnaissance analyst.
Your job is to quickly analyze data and extract security-relevant information.
Be concise and precise. Format output as structured data when possible.
Focus on: subdomains, endpoints, parameters, technologies, potential vulnerabilities."""

    RESPONSE_ANALYSIS_PROMPT = """You are analyzing HTTP responses for security issues.
Look for: error messages, stack traces, sensitive data leaks, version disclosures,
debug information, internal IPs, credentials, API keys, tokens.
Report findings in a structured format with severity ratings."""

    PATTERN_MATCHING_PROMPT = """You are a pattern matching specialist.
Analyze the provided data and identify patterns relevant to security testing.
Extract: URLs, endpoints, parameters, IDs, tokens, interesting strings.
Be thorough but concise."""

    REPORT_FORMATTING_PROMPT = """You are a security report formatter.
Take raw findings and format them into clear, professional reports.
Include: title, severity, description, reproduction steps, impact, remediation.
Use markdown formatting."""

    def __init__(self, config: Optional[AIConfig] = None):
        # Default to Haiku model
        if config is None:
            config = AIConfig(model="claude-3-5-haiku-20241022")
        elif "haiku" not in config.model.lower():
            # Force Haiku for grunt work
            config.model = "claude-3-5-haiku-20241022"

        super().__init__(config)
        self.tasks_completed = 0

    async def analyze_responses(self, responses: List[Dict]) -> List[Dict]:
        """
        Analyze multiple HTTP responses for security issues.
        Perfect grunt work - bulk analysis!
        """
        self.set_system_prompt(self.RESPONSE_ANALYSIS_PROMPT)

        findings = []

        # Process in batches
        batch_size = 5
        for i in range(0, len(responses), batch_size):
            batch = responses[i:i + batch_size]

            prompt = "Analyze these HTTP responses for security issues:\n\n"
            for j, resp in enumerate(batch):
                prompt += f"=== Response {i+j+1} ===\n"
                prompt += f"URL: {resp.get('url', 'N/A')}\n"
                prompt += f"Status: {resp.get('status', 'N/A')}\n"
                prompt += f"Headers: {json.dumps(resp.get('headers', {}), indent=2)}\n"
                prompt += f"Body (truncated): {str(resp.get('body', ''))[:2000]}\n\n"

            prompt += "\nReturn findings as JSON array with: url, issue, severity, evidence"

            result = await self.complete(prompt)

            # Try to parse JSON from response
            try:
                # Find JSON in response
                json_start = result.find('[')
                json_end = result.rfind(']') + 1
                if json_start >= 0 and json_end > json_start:
                    batch_findings = json.loads(result[json_start:json_end])
                    findings.extend(batch_findings)
            except json.JSONDecodeError:
                # If not valid JSON, store raw analysis
                findings.append({
                    "raw_analysis": result,
                    "batch_start": i
                })

            self.tasks_completed += 1

        return findings

    async def extract_endpoints(self, content: str) -> List[str]:
        """Extract API endpoints from JavaScript/HTML content"""
        self.set_system_prompt(self.PATTERN_MATCHING_PROMPT)

        prompt = f"""Extract all API endpoints and URLs from this content.
Return as a JSON array of strings.

Content:
{content[:10000]}

Return ONLY the JSON array, no explanation."""

        result = await self.complete(prompt)
        self.tasks_completed += 1

        try:
            json_start = result.find('[')
            json_end = result.rfind(']') + 1
            if json_start >= 0 and json_end > json_start:
                return json.loads(result[json_start:json_end])
        except Exception:
            pass

        return []

    async def extract_parameters(self, content: str) -> List[str]:
        """Extract parameter names from content"""
        self.set_system_prompt(self.PATTERN_MATCHING_PROMPT)

        prompt = f"""Extract all parameter names that might be used in API calls.
Look for: query parameters, JSON keys, form fields, headers.
Return as a JSON array of strings.

Content:
{content[:10000]}

Return ONLY the JSON array, no explanation."""

        result = await self.complete(prompt)
        self.tasks_completed += 1

        try:
            json_start = result.find('[')
            json_end = result.rfind(']') + 1
            if json_start >= 0 and json_end > json_start:
                return json.loads(result[json_start:json_end])
        except Exception:
            pass

        return []

    async def classify_vulnerability(self, finding: Dict) -> Dict:
        """Classify and enrich a vulnerability finding"""
        prompt = f"""Classify this security finding:

{json.dumps(finding, indent=2)}

Return JSON with:
- owasp_category (e.g., "A01:2021 - Broken Access Control")
- cwe_id (number)
- severity (critical/high/medium/low/info)
- exploitability (easy/medium/hard)
- impact_description
- remediation_suggestion

Return ONLY valid JSON."""

        result = await self.complete(prompt)
        self.tasks_completed += 1

        try:
            json_start = result.find('{')
            json_end = result.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                enriched = json.loads(result[json_start:json_end])
                return {**finding, **enriched}
        except Exception:
            pass

        return finding

    async def parse_recon_data(self, raw_data: str, data_type: str = "generic") -> Dict:
        """Parse raw reconnaissance data into structured format"""
        self.set_system_prompt(self.RECON_PROMPT)

        prompt = f"""Parse this {data_type} reconnaissance data into structured JSON.

Raw data:
{raw_data[:15000]}

Return JSON with relevant fields based on the data type.
For subdomains: {{"subdomains": [...], "live": [...], "technologies": {{}}}}
For endpoints: {{"endpoints": [...], "methods": [...], "parameters": [...]}}
For generic: {{"findings": [...], "interesting": [...], "next_steps": [...]}}

Return ONLY valid JSON."""

        result = await self.complete(prompt)
        self.tasks_completed += 1

        try:
            json_start = result.find('{')
            json_end = result.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                return json.loads(result[json_start:json_end])
        except Exception:
            pass

        return {"raw": raw_data, "parsed": False}

    async def format_report(self, findings: List[Dict], template: str = "hackerone") -> str:
        """Format findings into a bug bounty report"""
        self.set_system_prompt(self.REPORT_FORMATTING_PROMPT)

        templates = {
            "hackerone": """Format for HackerOne:
## Summary
## Severity
## Steps to Reproduce
## Impact
## Supporting Material/References
## Remediation""",
            "bugcrowd": """Format for Bugcrowd with VRT classification""",
            "generic": """Standard security report format"""
        }

        prompt = f"""Create a professional bug bounty report from these findings:

{json.dumps(findings, indent=2)}

{templates.get(template, templates['generic'])}

Write a complete, submission-ready report."""

        result = await self.complete(prompt)
        self.tasks_completed += 1

        return result

    async def bulk_analyze(self,
                          items: List[Any],
                          analysis_prompt: str,
                          batch_size: int = 10) -> List[Dict]:
        """
        Generic bulk analysis - the ultimate grunt work!

        Send in the infantry! 🎖️
        """
        results = []

        for i in range(0, len(items), batch_size):
            batch = items[i:i + batch_size]

            prompt = f"""{analysis_prompt}

Items to analyze:
{json.dumps(batch, indent=2, default=str)}

Return results as JSON array."""

            result = await self.complete(prompt)

            try:
                json_start = result.find('[')
                json_end = result.rfind(']') + 1
                if json_start >= 0 and json_end > json_start:
                    batch_results = json.loads(result[json_start:json_end])
                    results.extend(batch_results)
            except Exception:
                results.append({"batch": i, "raw": result})

            self.tasks_completed += 1

        return results

    def status_report(self) -> str:
        """Get grunt status report"""
        return f"""
🎖️ HAIKU GRUNT STATUS REPORT 🎖️
================================
Tasks Completed: {self.tasks_completed}
Total Tokens Used: {self.total_tokens_used}
Model: {self.config.model}
Status: READY FOR DUTY, SIR!
================================
"""


# Convenience functions
async def create_haiku_grunt(api_key: Optional[str] = None,
                            use_bedrock: bool = False) -> HaikuGrunt:
    """Create a Haiku grunt ready for action"""

    if use_bedrock:
        config = AIConfig(
            provider=AIProvider.BEDROCK,
            model="claude-3-5-haiku-20241022"
        )
    else:
        config = AIConfig(
            provider=AIProvider.ANTHROPIC,
            api_key=api_key,
            model="claude-3-5-haiku-20241022"
        )

    return HaikuGrunt(config)


async def quick_analyze(content: str, task: str = "security") -> str:
    """Quick one-shot analysis with Haiku"""
    grunt = HaikuGrunt()

    prompts = {
        "security": "Analyze for security vulnerabilities:",
        "endpoints": "Extract API endpoints:",
        "secrets": "Look for exposed secrets, keys, tokens:",
        "tech": "Identify technologies and versions:",
    }

    prompt = f"{prompts.get(task, prompts['security'])}\n\n{content}"
    return await grunt.complete(prompt)
