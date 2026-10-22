"""DeepSeek chat client (OpenAI-compatible API) with retries and a full call log.

Settings verified against api-docs.deepseek.com on 2026-10-16: base_url https://api.deepseek.com, models
deepseek-flash / deepseek-v4-pro, thinking mode on by default and switched off with
extra_body={"thinking": {"type": "disabled"}}; in thinking mode temperature has no effect.
Every request/response is appended to <run_dir>/llm_calls.jsonl so each agent decision can be audited.
One LLM object may be called from several threads at once (the hunt's planning batches and triage families run in
parallel): the counters and the log file are updated under a lock, and every call returns its own finish_reason.
"""
import hashlib
import json
import threading
import time

from openai import OpenAI

from . import config


class LLM:
    def __init__(self, run_dir, temperature: float = 0.0, thinking: bool = False, model: str | None = None,
                 max_retries: int = 3):
        s = config.llm_settings()
        if not s["api_key"]:
            raise RuntimeError("DEEPSEEK_API_KEY is empty in .env")
        self.client = OpenAI(api_key=s["api_key"], base_url=s["base_url"], timeout=180)
        self.model = model or s["model"]
        self.temperature = temperature
        self.thinking = thinking
        self.max_retries = max_retries
        self.log_path = run_dir / "llm_calls.jsonl"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.calls = 0
        self.tokens = {"prompt": 0, "completion": 0}
        self._lock = threading.Lock()

    def chat(self, messages: list, tools: list | None = None, json_mode: bool = False, purpose: str = ""):
        return self.chat_with_finish(messages, tools, json_mode, purpose)[0]

    def chat_with_finish(self, messages: list, tools: list | None = None, json_mode: bool = False, purpose: str = ""):
        """chat() plus the response's finish_reason ("length" = cut off at the output token limit). Until 2026-10-22
        the hunt read finish_reason back from the last line of llm_calls.jsonl, which is wrong once calls run in
        parallel: the last line may belong to another call."""
        kwargs = {"model": self.model, "messages": messages,
                  "extra_body": {"thinking": {"type": "enabled" if self.thinking else "disabled"}}}
        if not self.thinking:
            kwargs["temperature"] = self.temperature
        if tools:
            kwargs["tools"] = tools
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        last = None
        for attempt in range(1, self.max_retries + 1):
            t0 = time.time()
            try:
                resp = self.client.chat.completions.create(**kwargs)
                break
            except Exception as exc:   # network errors, 429, 5xx
                last = exc
                time.sleep(2 ** attempt)
        else:
            raise RuntimeError(f"LLM call failed after {self.max_retries} attempts: {last}")
        msg = resp.choices[0].message
        finish = resp.choices[0].finish_reason
        record = json.dumps({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "purpose": purpose, "model": resp.model,
            "temperature": kwargs.get("temperature"), "thinking": self.thinking, "attempt": attempt,
            "latency_s": round(time.time() - t0, 2),
            "prompt_sha256": hashlib.sha256(json.dumps(messages, sort_keys=True, default=str).encode()).hexdigest(),
            "messages": messages, "tools": [t["function"]["name"] for t in tools or []],
            "response": msg.model_dump(exclude_none=True), "finish_reason": finish,
            "usage": resp.usage.model_dump() if resp.usage else None,
        }, ensure_ascii=False, default=str) + "\n"
        with self._lock:
            self.calls += 1
            if resp.usage:
                self.tokens["prompt"] += resp.usage.prompt_tokens
                self.tokens["completion"] += resp.usage.completion_tokens
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(record)
        return msg, finish
