"""A real LangChain toy agent, instrumented by Traceloop's real
opentelemetry-instrumentation-langchain, exported over real OTLP/HTTP to a
real opentelemetry-collector-contrib file exporter.

No weir code anywhere in this pipeline: the gen_ai.* semantics are
authored by the instrumentation library, the wire bytes by the collector.
"""

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

provider = TracerProvider()
provider.add_span_processor(
    BatchSpanProcessor(OTLPSpanExporter(endpoint="http://127.0.0.1:4318/v1/traces"))
)
trace.set_tracer_provider(provider)

from opentelemetry.instrumentation.langchain import LangchainInstrumentor

LangchainInstrumentor().instrument()

from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.tools import tool


@tool
def lookup(query: str) -> str:
    """Look up a fact in the knowledge base."""
    return "Paris"


question = HumanMessage(content="What is the capital of France?")
scripted = iter(
    [
        AIMessage(
            content="",
            tool_calls=[
                {"name": "lookup", "args": {"query": "capital of France"}, "id": "call_001"}
            ],
        ),
        AIMessage(content="The capital of France is Paris."),
    ]
)
model = GenericFakeChatModel(messages=scripted)

first = model.invoke([question])
tool_result = lookup.invoke(first.tool_calls[0]["args"])
final = model.invoke(
    [question, first, ToolMessage(content=tool_result, tool_call_id="call_001")]
)
print("agent said:", final.content)

provider.force_flush()
provider.shutdown()
print("spans flushed")
