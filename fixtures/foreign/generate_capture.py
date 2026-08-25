"""Generates capture.jsonl - run ONCE by a human, never in CI (span ids and
timestamps are real and nondeterministic; the committed file is frozen).

Toy agent: user asks a question; the agent calls a lookup tool with an
explicit tool_call_id; the tool answers; the agent replies. Instrumented by
hand with opentelemetry-sdk gen_ai attributes (v1.42-style), exported in TWO
batches -> two JSONL lines, serialized by protobuf's official protojson
(camelCase keys, BASE64 ids, string nanos) - the wire realities amendment B
and the key-case decision exist for.
"""

import json

from google.protobuf import json_format
from opentelemetry.exporter.otlp.proto.common.trace_encoder import encode_spans
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)
from opentelemetry.trace import SpanKind

exporter = InMemorySpanExporter()
provider = TracerProvider()
provider.add_span_processor(SimpleSpanProcessor(exporter))
tracer = provider.get_tracer("opentelemetry.instrumentation.toyagent", "0.9")

# user_turn: INTERNAL (user input); call: CLIENT; result: INTERNAL; reply: CLIENT
with tracer.start_as_current_span("chat assistant") as user_turn:
    user_turn.set_attribute("gen_ai.operation.name", "chat")
    user_turn.set_attribute("gen_ai.provider.name", "toyagent")
    user_turn.set_attribute("gen_ai.input.messages", json.dumps(
        [{"role": "user", "content": "what is the capital of France?"}]))
    with tracer.start_as_current_span("execute_tool lookup", kind=SpanKind.CLIENT) as call:
        call.set_attribute("gen_ai.operation.name", "execute_tool")
        call.set_attribute("gen_ai.provider.name", "toyagent")
        call.set_attribute("gen_ai.tool.name", "lookup")
        call.set_attribute("gen_ai.tool.call.id", "call_001")
        call.set_attribute("gen_ai.tool.call.arguments",
                           json.dumps({"query": "capital of France"}))
        with tracer.start_as_current_span("execute_tool lookup") as result:
            result.set_attribute("gen_ai.operation.name", "execute_tool")
            result.set_attribute("gen_ai.provider.name", "toyagent")
            result.set_attribute("gen_ai.tool.call.id", "call_001")
            result.set_attribute("gen_ai.tool.call.result", "Paris")

batch1 = exporter.get_finished_spans()
exporter.clear()

with tracer.start_as_current_span("chat assistant", kind=SpanKind.CLIENT) as reply:
    reply.set_attribute("gen_ai.operation.name", "chat")
    reply.set_attribute("gen_ai.provider.name", "toyagent")
    reply.set_attribute("gen_ai.output.messages", json.dumps(
        [{"role": "assistant", "content": "Paris."}]))

batch2 = exporter.get_finished_spans()

with open("capture.jsonl", "w", encoding="utf-8", newline="\n") as f:
    for batch in (batch1, batch2):
        request = encode_spans(batch)
        # use_integers_for_enums: OTLP/JSON's canonical `kind` is an int
        # (json_format's default prints the enum NAME as a string, which
        # this repo's other OTLP fixtures do not use and the adapter's
        # WireSpan.kind: int does not accept).
        f.write(json_format.MessageToJson(
            request, indent=None, use_integers_for_enums=True,
        ).replace("\n", "") + "\n")
print("wrote capture.jsonl - commit it and never regenerate silently")
